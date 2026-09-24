declare module 'whois-json' {
  function whoisJson(domain: string, options?: any): Promise<any>;
  export = whoisJson;
}
