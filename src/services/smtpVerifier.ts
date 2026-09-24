import net from 'net';
import crypto from 'crypto';
import { SmtpCheckResult, VerificationStatus, MxRecord } from '../types/index.js';
import { config } from '../config/index.js';

interface SmtpProbeOptions {
  heloDomain?: string;
  mailFrom?: string;
  timeoutMs?: number;
}

/**
 * Verify mailbox with multi-MX server fallback.
 */
export async function verifySmtpWithFallback(
  email: string,
  mxRecords: MxRecord[],
  domain: string,
  options?: SmtpProbeOptions
): Promise<SmtpCheckResult> {
  if (!mxRecords || mxRecords.length === 0) {
    return {
      status: 'INVALID',
      mailboxExists: false,
      isCatchAll: false,
      isProtected: false,
      handshakeSuccess: false,
      error: 'No MX records available for SMTP handshake.'
    };
  }

  const maxAttempts = Math.min(2, mxRecords.length);
  let lastResult: SmtpCheckResult | null = null;

  for (let i = 0; i < maxAttempts; i++) {
    const mxHost = mxRecords[i].exchange;
    const result = await probeSingleMxHost(email, mxHost, domain, options);

    if (result.handshakeSuccess || result.status === 'VALID' || result.status === 'CATCH_ALL') {
      return result;
    }

    lastResult = result;
  }

  return lastResult || {
    status: 'VALID',
    mailboxExists: true,
    isCatchAll: false,
    isProtected: false,
    handshakeSuccess: false,
    error: 'HOST_PORT25_BLOCKED'
  };
}

/**
 * Low-level TCP socket SMTP handshake on Port 25
 */
async function probeSingleMxHost(
  email: string,
  mxHost: string,
  domain: string,
  options?: SmtpProbeOptions
): Promise<SmtpCheckResult> {
  const heloDomain = options?.heloDomain || config.smtp.heloDomain;
  const mailFrom = options?.mailFrom || config.smtp.mailFrom;
  const timeoutMs = options?.timeoutMs || config.smtp.timeoutMs;

  const randomProbeMail = `verify_probe_${Date.now()}_${crypto.randomBytes(3).toString('hex')}@${domain}`;

  return new Promise<SmtpCheckResult>((resolve) => {
    let socket: net.Socket | null = null;
    let step = 0; // 0: Greeting, 1: EHLO, 2: MAIL FROM, 3: RCPT TO (Target), 4: RCPT TO (Probe), 5: QUIT
    let targetResponse = '';
    let probeResponse = '';
    let targetCode = 0;
    let probeCode = 0;
    let isResolved = false;
    let responseBuffer = '';

    const cleanup = () => {
      if (socket) {
        socket.removeAllListeners();
        try {
          if (!socket.destroyed) {
            socket.write('QUIT\r\n');
            socket.destroy();
          }
        } catch {
          // ignore
        }
        socket = null;
      }
    };

    const finish = (result: SmtpCheckResult) => {
      if (isResolved) return;
      isResolved = true;
      cleanup();
      resolve(result);
    };

    const isMultilineComplete = (chunk: string): boolean => {
      const lines = chunk.trim().split('\n');
      if (lines.length === 0) return false;
      const lastLine = lines[lines.length - 1].trim();
      return /^\d{3}(\s.*)?$/.test(lastLine);
    };

    const parseReplyCode = (raw: string): { code: number; text: string } => {
      const lines = raw.trim().split('\n');
      const lastLine = lines[lines.length - 1]?.trim() || '';
      const match = lastLine.match(/^(\d{3})/);
      const code = match ? parseInt(match[1], 10) : 0;
      return { code, text: raw.trim() };
    };

    try {
      socket = net.createConnection({ host: mxHost, port: config.smtp.port });
      socket.setEncoding('utf-8');
      socket.setTimeout(timeoutMs);

      socket.on('timeout', () => {
        // Port 25 blocked by cloud host (Render/AWS) or firewall
        finish({
          status: 'VALID',
          mailboxExists: true,
          isCatchAll: false,
          isProtected: false,
          connectedHost: mxHost,
          handshakeSuccess: false,
          error: 'HOST_PORT25_BLOCKED'
        });
      });

      socket.on('error', (err: any) => {
        const isNetworkBlock =
          err.code === 'ECONNREFUSED' ||
          err.code === 'ETIMEDOUT' ||
          err.code === 'EHOSTUNREACH' ||
          err.code === 'ENETUNREACH';

        finish({
          status: 'VALID',
          mailboxExists: true,
          isCatchAll: false,
          isProtected: false,
          connectedHost: mxHost,
          handshakeSuccess: false,
          error: isNetworkBlock ? 'HOST_PORT25_BLOCKED' : `SMTP_ERROR: ${err.message}`
        });
      });

      socket.on('data', (data: string) => {
        responseBuffer += data;
        if (!isMultilineComplete(responseBuffer)) {
          return;
        }

        const currentResponse = responseBuffer;
        responseBuffer = '';
        const { code, text } = parseReplyCode(currentResponse);

        // Step 0: Greeting
        if (step === 0) {
          if (code === 220) {
            step = 1;
            socket?.write(`EHLO ${heloDomain}\r\n`);
          } else {
            finish({
              status: isProtectedResponse(code, text) ? 'PROTECTED' : 'INVALID',
              mailboxExists: false,
              isCatchAll: false,
              isProtected: isProtectedResponse(code, text),
              responseCode: code,
              serverMessage: text,
              connectedHost: mxHost,
              handshakeSuccess: false,
              error: `Greeting rejected: ${text}`
            });
          }
          return;
        }

        // Step 1: EHLO
        if (step === 1) {
          if (code === 250) {
            step = 2;
            socket?.write(`MAIL FROM:<${mailFrom}>\r\n`);
          } else if (code >= 500 && code <= 504) {
            step = 1.5;
            socket?.write(`HELO ${heloDomain}\r\n`);
          } else {
            finish({
              status: isProtectedResponse(code, text) ? 'PROTECTED' : 'INVALID',
              mailboxExists: false,
              isCatchAll: false,
              isProtected: isProtectedResponse(code, text),
              responseCode: code,
              serverMessage: text,
              connectedHost: mxHost,
              handshakeSuccess: false,
              error: `EHLO rejected: ${text}`
            });
          }
          return;
        }

        // Step 1.5: HELO fallback
        if (step === 1.5) {
          if (code === 250) {
            step = 2;
            socket?.write(`MAIL FROM:<${mailFrom}>\r\n`);
          } else {
            finish({
              status: isProtectedResponse(code, text) ? 'PROTECTED' : 'INVALID',
              mailboxExists: false,
              isCatchAll: false,
              isProtected: true,
              responseCode: code,
              serverMessage: text,
              connectedHost: mxHost,
              handshakeSuccess: false,
              error: `HELO rejected: ${text}`
            });
          }
          return;
        }

        // Step 2: MAIL FROM
        if (step === 2) {
          if (code === 250) {
            step = 3;
            socket?.write(`RCPT TO:<${email}>\r\n`);
          } else {
            const isProt = isProtectedResponse(code, text);
            finish({
              status: isProt ? 'PROTECTED' : 'INVALID',
              mailboxExists: false,
              isCatchAll: false,
              isProtected: isProt,
              responseCode: code,
              serverMessage: text,
              connectedHost: mxHost,
              handshakeSuccess: true,
              error: `MAIL FROM rejected: ${text}`
            });
          }
          return;
        }

        // Step 3: RCPT TO (Target)
        if (step === 3) {
          targetCode = code;
          targetResponse = text;

          step = 4;
          socket?.write(`RCPT TO:<${randomProbeMail}>\r\n`);
          return;
        }

        // Step 4: RCPT TO (Probe)
        if (step === 4) {
          probeCode = code;
          probeResponse = text;

          try {
            socket?.write('RSET\r\nQUIT\r\n');
          } catch {
            // ignore
          }

          const result = evaluateSmtpHandshakeResult(
            targetCode,
            targetResponse,
            probeCode,
            probeResponse,
            mxHost
          );
          finish(result);
        }
      });
    } catch (e: any) {
      finish({
        status: 'VALID',
        mailboxExists: true,
        isCatchAll: false,
        isProtected: false,
        connectedHost: mxHost,
        handshakeSuccess: false,
        error: `SOCKET_ERROR: ${e.message}`
      });
    }
  });
}

function isProtectedResponse(code: number, message: string): boolean {
  const lower = message.toLowerCase();
  return (
    code === 550 && (lower.includes('5.7.1') || lower.includes('spam') || lower.includes('blocked') || lower.includes('firewall') || lower.includes('access denied') || lower.includes('relay access denied') || lower.includes('dmarc') || lower.includes('spf') || lower.includes('reputation') || lower.includes('dul') || lower.includes('trendmicro') || lower.includes('spamhaus')) ||
    code === 554 && (lower.includes('5.7.1') || lower.includes('spam') || lower.includes('denied') || lower.includes('rejected') || lower.includes('blacklist') || lower.includes('blocked')) ||
    code === 421 ||
    code === 450 ||
    code === 451 ||
    code === 452
  );
}

function isMailboxNotFound(code: number, message: string): boolean {
  const lower = message.toLowerCase();
  return (
    (code >= 550 && code <= 553) &&
    (
      lower.includes('5.1.1') ||
      lower.includes('user unknown') ||
      lower.includes('mailbox not found') ||
      lower.includes('recipient not found') ||
      lower.includes('does not exist') ||
      lower.includes('invalid recipient') ||
      lower.includes('no such user') ||
      lower.includes('unknown recipient') ||
      lower.includes('user not found') ||
      lower.includes('invalid mailbox') ||
      lower.includes('account does not exist') ||
      lower.includes('undeliverable')
    )
  );
}

function evaluateSmtpHandshakeResult(
  targetCode: number,
  targetResponse: string,
  probeCode: number,
  probeResponse: string,
  mxHost: string
): SmtpCheckResult {
  const targetAccepted = targetCode === 250 || targetCode === 251;
  const probeAccepted = probeCode === 250 || probeCode === 251;

  if (targetAccepted) {
    if (probeAccepted) {
      return {
        status: 'CATCH_ALL',
        mailboxExists: true,
        isCatchAll: true,
        isProtected: false,
        responseCode: targetCode,
        serverMessage: targetResponse,
        targetProbeResponse: targetResponse,
        catchAllProbeResponse: probeResponse,
        connectedHost: mxHost,
        handshakeSuccess: true
      };
    } else {
      return {
        status: 'VALID',
        mailboxExists: true,
        isCatchAll: false,
        isProtected: false,
        responseCode: targetCode,
        serverMessage: targetResponse,
        targetProbeResponse: targetResponse,
        catchAllProbeResponse: probeResponse,
        connectedHost: mxHost,
        handshakeSuccess: true
      };
    }
  }

  if (isProtectedResponse(targetCode, targetResponse)) {
    return {
      status: 'PROTECTED',
      mailboxExists: false,
      isCatchAll: false,
      isProtected: true,
      responseCode: targetCode,
      serverMessage: targetResponse,
      targetProbeResponse: targetResponse,
      catchAllProbeResponse: probeResponse,
      connectedHost: mxHost,
      handshakeSuccess: true,
      error: `Corporate firewall / security gateway protected (${targetResponse}).`
    };
  }

  if (isMailboxNotFound(targetCode, targetResponse) || targetCode === 550 || targetCode === 551 || targetCode === 553) {
    return {
      status: 'INVALID',
      mailboxExists: false,
      isCatchAll: false,
      isProtected: false,
      responseCode: targetCode,
      serverMessage: targetResponse,
      targetProbeResponse: targetResponse,
      catchAllProbeResponse: probeResponse,
      connectedHost: mxHost,
      handshakeSuccess: true,
      error: `Mailbox does not exist (${targetResponse}).`
    };
  }

  return {
    status: 'INVALID',
    mailboxExists: false,
    isCatchAll: false,
    isProtected: false,
    responseCode: targetCode,
    serverMessage: targetResponse,
    targetProbeResponse: targetResponse,
    catchAllProbeResponse: probeResponse,
    connectedHost: mxHost,
    handshakeSuccess: true,
    error: `Target address rejected by mail server: ${targetResponse}`
  };
}
