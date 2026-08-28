// src/mitm/CertificateAuthority.ts
// In-memory X.509 Certificate Authority class.
//
// Single responsibility: Certificate generation and caching. No OS trust store logic.

import forge from 'node-forge';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { generateKeyPairSync, randomBytes } from 'crypto';
import type { CaMaterials, DomainCreds } from '../types.js';

export class CertificateAuthority {
  private caKeys: forge.pki.KeyPair | null = null;
  private caCert: forge.pki.Certificate | null = null;
  private readonly domainCertCache = new Map<string, DomainCreds>();

  /**
   * Generates a 2048-bit RSA Root CA in memory and writes only the public
   * certificate to a temp file so NODE_EXTRA_CA_CERTS can reference it.
   */
  initCA(): CaMaterials {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding:  { type: 'spki',  format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    this.caKeys = {
      privateKey: forge.pki.privateKeyFromPem(privateKey),
      publicKey:  forge.pki.publicKeyFromPem(publicKey),
    };

    this.caCert = forge.pki.createCertificate();
    this.caCert.publicKey = this.caKeys.publicKey;
    this.caCert.serialNumber = '01';
    this.caCert.validity.notBefore = new Date();
    this.caCert.validity.notAfter  = new Date();
    this.caCert.validity.notAfter.setFullYear(this.caCert.validity.notBefore.getFullYear() + 10);

    const attrs = this.makeAttrs('envtrap Root CA');
    this.caCert.setSubject(attrs);
    this.caCert.setIssuer(attrs);
    this.caCert.setExtensions([
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
      { name: 'subjectKeyIdentifier' },
    ]);

    this.caCert.sign(this.caKeys.privateKey as forge.pki.rsa.PrivateKey, forge.md.sha256.create());

    const certPem  = forge.pki.certificateToPem(this.caCert);
    const certPath = path.join(os.tmpdir(), 'envtrap-ca.crt');
    fs.writeFileSync(certPath, certPem, { encoding: 'utf-8', mode: 0o600 });

    return { certPem, certPath };
  }

  /**
   * Generates (or retrieves from cache) a TLS certificate for hostname,
   * signed by the in-memory Root CA.
   */
  generateDomainCert(hostname: string): DomainCreds {
    if (!this.caKeys || !this.caCert) {
      throw new Error('[envtrap/ca] initCA() must be called before generateDomainCert()');
    }

    const host = hostname.split(':')[0]; // strip port if present

    const cached = this.domainCertCache.get(host);
    if (cached) return cached;

    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding:  { type: 'spki',  format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const domainKeys = {
      privateKey: forge.pki.privateKeyFromPem(privateKey),
      publicKey:  forge.pki.publicKeyFromPem(publicKey),
    };

    const domainCert = forge.pki.createCertificate();
    domainCert.publicKey    = domainKeys.publicKey;
    domainCert.serialNumber = randomBytes(20).toString('hex');

    domainCert.validity.notBefore = new Date();
    domainCert.validity.notAfter  = new Date();
    domainCert.validity.notAfter.setFullYear(domainCert.validity.notBefore.getFullYear() + 1);

    domainCert.setSubject(this.makeAttrs(host));
    domainCert.setIssuer(this.caCert.subject.attributes);
    domainCert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
      { name: 'extKeyUsage', serverAuth: true },
      {
        name: 'subjectAltName',
        altNames: [
          { type: 2, value: host },
          { type: 2, value: `*.${host}` },
        ],
      },
    ]);

    domainCert.sign(this.caKeys.privateKey as forge.pki.rsa.PrivateKey, forge.md.sha256.create());

    const creds: DomainCreds = {
      keyPem:  forge.pki.privateKeyToPem(domainKeys.privateKey),
      certPem: forge.pki.certificateToPem(domainCert),
    };

    this.domainCertCache.set(host, creds);
    return creds;
  }

  getCacheSize(): number {
    return this.domainCertCache.size;
  }

  private makeAttrs(commonName: string): forge.pki.CertificateField[] {
    return [
      { name: 'commonName',            value: commonName },
      { name: 'organizationName',      value: 'envtrap Local CA' },
      { name: 'organizationalUnitName', value: 'envtrap v2.1' },
      { name: 'countryName',           value: 'US' },
    ];
  }
}
