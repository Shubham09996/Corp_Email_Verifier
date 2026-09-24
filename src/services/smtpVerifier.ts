import net from 'net';
import crypto from 'crypto';
import { SmtpCheckResult, VerificationStatus } from '../types/index.js';
import { config } from '../config/index.js';

interface SmtpProbeOptions {
  heloDomain?: string;
  mailFrom?: string;
  timeoutMs?: number;
}

/**
 * Perform low-level TCP SMTP handshake on port 25 to verify mailbox existence and catch-all status.
 */
export async function verifySmtpMailbox(
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
      // An SMTP reply line is complete if it matches ^\d{3}\s or single line ^\d{3}$
      return /^\d{3}(\s.*)?$/.test(lastLine);
    };

    const parseReplyCode = (raw: string): { code: number; text: string } => {
      const lines = raw.trim().split('\n');
      const lastLine = lines[lines.length - 1]?.trim() || '';
      const match = lastLine.match(/^(\d{3})/);
      const code = match ? parseInt(match[1], 10) : 0;
      return { code, text: raw.trim() };
    };

    // Initialize TCP socket connection
    try {
      socket = net.createConnection({ host: mxHost, port: config.smtp.port }, () => {
        // Socket connected, waiting for 220 greeting
      });

      socket.setEncoding('utf-8');
      socket.setTimeout(timeoutMs);

      socket.on('timeout', () => {
        finish({
          status: 'PROTECTED',
          mailboxExists: false,
          isCatchAll: false,
          isProtected: true,
          connectedHost: mxHost,
          handshakeSuccess: false,
          error: `SMTP connection to ${mxHost}:25 timed out after ${timeoutMs}ms (likely blocked by firewall or ISP port 25 restriction).`
        });
      });

      socket.on('error', (err: any) => {
        const isFirewallOrBlocked =
          err.code === 'ECONNREFUSED' ||
          err.code === 'ETIMEDOUT' ||
          err.code === 'EHOSTUNREACH' ||
          err.code === 'ENETUNREACH';

        finish({
          status: isFirewallOrBlocked ? 'PROTECTED' : 'INVALID',
          mailboxExists: false,
          isCatchAll: false,
          isProtected: isFirewallOrBlocked,
          connectedHost: mxHost,
          handshakeSuccess: false,
          error: `SMTP connection error (${err.code || err.message}).`
        });
      });

      socket.on('data', (data: string) => {
        responseBuffer += data;
        if (!isMultilineComplete(responseBuffer)) {
          return; // Wait for full SMTP multiline response
        }

        const currentResponse = responseBuffer;
        responseBuffer = '';
        const { code, text } = parseReplyCode(currentResponse);

        // Step 0: Initial 220 Greeting from server
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
              error: `Unexpected SMTP greeting code ${code}: ${text}`
            });
          }
          return;
        }

        // Step 1: EHLO Response
        if (step === 1) {
          if (code === 250) {
            step = 2;
            socket?.write(`MAIL FROM:<${mailFrom}>\r\n`);
          } else if (code >= 500 && code <= 504) {
            // Fallback to HELO if EHLO not supported
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
              error: `EHLO rejected with code ${code}: ${text}`
            });
          }
          return;
        }

        // Step 1.5: HELO fallback Response
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
              error: `HELO rejected with code ${code}: ${text}`
            });
          }
          return;
        }

        // Step 2: MAIL FROM Response
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

        // Step 3: RCPT TO (Applicant Target Mailbox)
        if (step === 3) {
          targetCode = code;
          targetResponse = text;

          // Now probe for catch-all
          step = 4;
          socket?.write(`RCPT TO:<${randomProbeMail}>\r\n`);
          return;
        }

        // Step 4: RCPT TO (Random Probe for Catch-All detection)
        if (step === 4) {
          probeCode = code;
          probeResponse = text;

          // Send RSET and QUIT to cleanly close
          try {
            socket?.write('RSET\r\nQUIT\r\n');
          } catch {
            // ignore
          }

          // Evaluate the combined results
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
        status: 'PROTECTED',
        mailboxExists: false,
        isCatchAll: false,
        isProtected: true,
        connectedHost: mxHost,
        handshakeSuccess: false,
        error: `Failed to initiate socket: ${e.message}`
      });
    }
  });
}

/**
 * Check if the SMTP response code or text represents a corporate firewall, spam block, or greylisting.
 */
function isProtectedResponse(code: number, message: string): boolean {
  const lower = message.toLowerCase();
  return (
    code === 550 && (lower.includes('5.7.1') || lower.includes('spam') || lower.includes('blocked') || lower.includes('firewall') || lower.includes('access denied') || lower.includes('relay access denied') || lower.includes('dmarc') || lower.includes('spf') || lower.includes('reputation')) ||
    code === 554 && (lower.includes('5.7.1') || lower.includes('spam') || lower.includes('denied') || lower.includes('rejected') || lower.includes('blacklist') || lower.includes('blocked')) ||
    code === 421 || // Service not available, closing transmission channel
    code === 450 || // Mailbox temporarily unavailable / greylisting
    code === 451 || // Local error in processing
    code === 452    // Insufficient system storage
  );
}

/**
 * Check if the SMTP response indicates a non-existent mailbox.
 */
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

/**
 * Evaluate status based on applicant target probe and random fake probe.
 */
function evaluateSmtpHandshakeResult(
  targetCode: number,
  targetResponse: string,
  probeCode: number,
  probeResponse: string,
  mxHost: string
): SmtpCheckResult {
  const targetAccepted = targetCode === 250 || targetCode === 251;
  const probeAccepted = probeCode === 250 || probeCode === 251;

  // Case 1: Target was accepted (250)
  if (targetAccepted) {
    if (probeAccepted) {
      // Domain accepts anything -> Catch-All
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
      // Target accepted, Fake rejected -> Definitively Valid Mailbox!
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

  // Case 2: Target rejected due to Spam Firewall / Security Gateway (5.7.1, 4xx, Proofpoint, M365, etc.)
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
      error: `Corporate firewall / anti-spam protection detected (${targetResponse}).`
    };
  }

  // Case 3: Target rejected with Mailbox Not Found / 5.1.1
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

  // Fallback
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
