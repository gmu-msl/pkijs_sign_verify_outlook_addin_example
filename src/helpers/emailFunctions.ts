import { Crypto } from "@peculiar/webcrypto";
import * as asn1js from "asn1js";
import { Convert } from "pvtsutils";
import * as pkijs from "pkijs";

// Set crypto engine
const crypto = new Crypto();
const engineName = "@peculiar/webcrypto";
pkijs.setEngine(
  engineName,
  crypto,
  new pkijs.CryptoEngine({ name: engineName, crypto: crypto, subtle: crypto.subtle })
);

import { PemConverter } from "./converters";

import MimeNode from "emailjs-mime-builder";
import smimeParse from "emailjs-mime-parser";

/**
 * Adapted from PKI.js' CMSSignedComplexExample
 * @returns {String} signed string
 * @param {String} text string to sign
 * @param {String} privateKeyPem user's private key to sign with in PEM format
 * @param {String} certificatePem user's public cert to sign with in PEM format
 */
export async function smimeSign(
  text: string,
  privateKeyPem: string,
  certificatePem: string,
  signAlgo = "RSASSA-PKCS1-v1_5",
  hashAlgo = "SHA-256",
  modulusLength = 2048,
  addExt = false,
  detachedSignature = true
): Promise<string> {
  const alg = {
    name: signAlgo,
    hash: hashAlgo,
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: modulusLength,
  };

  // Decode input certificate
  const asn1 = asn1js.fromBER(PemConverter.decode(certificatePem)[0]);
  const certSimpl = new pkijs.Certificate({ schema: asn1.result });

  // Import key
  const pkcs8 = PemConverter.decode(privateKeyPem)[0];
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);

  const cmsSigned = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: "1.2.840.113549.1.7.1", // "data" content type
      eContent: new asn1js.OctetString({ valueHex: Convert.FromUtf8String(text) }),
    }),
    signerInfos: [
      new pkijs.SignerInfo({
        version: 1,
        sid: new pkijs.IssuerAndSerialNumber({
          issuer: certSimpl.issuer,
          serialNumber: certSimpl.serialNumber,
        }),
      }),
    ],
    certificates: [certSimpl],
  });

  await cmsSigned.sign(key, 0, hashAlgo);

  const cmsContentSimpl = new pkijs.ContentInfo();
  cmsContentSimpl.contentType = "1.2.840.113549.1.7.2";
  cmsContentSimpl.content = cmsSigned.toSchema();

  const schema = cmsContentSimpl.toSchema();
  const ber = schema.toBER(false);

  // Insert enveloped data into new Mime message
  const mimeBuilder = new MimeNode("application/pkcs7-mime; name=smime.p7m; smime-type=signed-data;")
    .setHeader("content-description", "Signed Data")
    .setHeader("content-disposition", "attachment; filename=smime.p7m")
    .setHeader("content-transfer-encoding", "base64")
    .setContent(new Uint8Array(ber));
  mimeBuilder.setHeader("from", "sender@example.com");
  mimeBuilder.setHeader("to", "recipient@example.com");
  mimeBuilder.setHeader("subject", "Example S/MIME signed message");

  return mimeBuilder.build();
}

export async function smimeSign2(
  text,
  privateKeyPem,
  certificatePem,
  signAlgo = "RSASSA-PKCS1-v1_5",
  hashAlgo = "SHA-256",
  modulusLength = 2048,
  addExt = false,
  detachedSignature = true
) {
  const alg = {
    name: signAlgo,
    hash: hashAlgo,
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: modulusLength,
  };

  // Decode input certificate
  const asn1 = asn1js.fromBER(PemConverter.decode(certificatePem)[0]);
  const certSimpl = new pkijs.Certificate({ schema: asn1.result });

  // Import key
  const pkcs8 = PemConverter.decode(privateKeyPem)[0];
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);

  const cmsSigned = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: "1.2.840.113549.1.7.1", // "data" content type
      eContent: new asn1js.OctetString({ valueHex: Convert.FromUtf8String(text) }),
    }),
    signerInfos: [
      new pkijs.SignerInfo({
        version: 1,
        sid: new pkijs.IssuerAndSerialNumber({
          issuer: certSimpl.issuer,
          serialNumber: certSimpl.serialNumber,
        }),
      }),
    ],
    certificates: [certSimpl],
  });

  await cmsSigned.sign(key, 0, hashAlgo);

  const cmsContentSimpl = new pkijs.ContentInfo();
  cmsContentSimpl.contentType = "1.2.840.113549.1.7.2";
  cmsContentSimpl.content = cmsSigned.toSchema();

  const schema = cmsContentSimpl.toSchema();
  const ber = schema.toBER(false);

  // Insert enveloped data into new Mime message
  const mimeBuilder = new MimeNode("application/pkcs7-mime; name=smime.p7m; smime-type=signed-data;")
    .setHeader("content-description", "Signed Data")
    .setHeader("content-disposition", "attachment; filename=smime.p7m")
    .setHeader("content-transfer-encoding", "base64")
    .setContent(new Uint8Array(ber));
  mimeBuilder.setHeader("from", "sender@example.com");
  mimeBuilder.setHeader("to", "recipient@example.com");
  mimeBuilder.setHeader("subject", "Example S/MIME signed message");

  return mimeBuilder.build();
}

export async function smimeVerify(smime: string, certificatePem: string) {
  // Parse S/MIME message to get CMS enveloped content
  const parser = smimeParse(smime);

  // Make all CMS data
  let asn1 = asn1js.fromBER(parser.content.buffer);
  if (asn1.offset === -1) {
    alert('Unable to parse your data. Please check you have "Content-Type: charset=binary" in your S/MIME message');
    return;
  }

  const cmsContentSimpl = new pkijs.ContentInfo({ schema: asn1.result });
  const cmsSignedSimpl = new pkijs.SignedData({ schema: cmsContentSimpl.content });

  // Decode input certificate
  asn1 = asn1js.fromBER(PemConverter.decode(certificatePem)[0]);
  const certSimpl = new pkijs.Certificate({ schema: asn1.result });

  // push certificate we got from DANE before verifying
  cmsSignedSimpl.certificates.push(certSimpl);

  const verificationParameters = {
    signer: 0,
    checkChain: false,
    extendedMode: true,
  };

  return cmsSignedSimpl.verify(verificationParameters);
}

/**
 * Adapted from PKI.js' SMIMEEncryptionExample
 * @returns {string} encrypted string
 * @param {string} text string to encrypt
 * @param {string} certificatePem public certificate to encrypt with in PEM format
 * @param {string} oaepHashAlgo algorithm to hash the text with (defaults to SHA-256)
 * @param {string} encryptionAlgo algorithm to encrypt the text with ("AES-CBC" or "AES-GCM")
 * @param {Number} length length to encrypt the text to (default 128)
 */
export async function smimeEncrypt(
  text: string,
  certificatePem: string,
  oaepHashAlgo: string = "SHA-256",
  encryptionAlgo: string = "AES-CBC",
  length: Number = 128
): Promise<string> {
  text = "This is some plaintext.";

  certificatePem =
    "------BEGIN CERTIFICATE-----\r\nMIIFYjCCA0oCAQEwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMRAwDgYDVQQHDAdGYWlyZmF4MQwwCgYDVQQKDANHTVUxDDAKBgNVBAsMA01TTDESMBAGA1UEAwwJSm9zaCBZdWVuMB4XDTIxMDUxMTAxMDAxOFoXDTMxMDUwOTAxMDAxOFowgYsxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhWaXJnaW5pYTEQMA4GA1UEBwwHRmFpcmZheDEMMAoGA1UECgwDR01VMQwwCgYDVQQLDANNU0wxEjAQBgNVBAMMCUpvc2ggWXVlbjEnMCUGCSqGSIb3DQEJARYYanl1ZW4yQG1hc29ubGl2ZS5nbXUuZWR1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtqqoLT0P8O5f14ZR2NlhO8VWRQbxxi2k9eXmV1RdzRfH2qhp6cM0SFtZ3O1yjlWA1QSYlLOYJbOgYXO2HMVGWmCTY1UEQgJIcQRlmv9G8P5IcQCVmPPgJtZq1M8n3rHdnbZ0eOdoikWv3BCyc4myupsiuFtETGdcQp02M33S+9yJWo+I0D5d9juMX3uCHBkQnQdU4u/shzYRgct1jX1PlXHZsFzLP/KtfrpPcReP6MEpB/ySneMMN++tFnN0CX1DfM2zOBXgTfQS9/QirN9saQS2MQGaB/vayjV+ELirFnzKsO02VHh77T8hIXDgsu1bnSVv8PpDDPhBPtXCSin8Xo50P09rVus/wnnh1xUyR6tTYoDx6aZKwcuX0gLyB4Hl+6qvqh3xCuS8ikrmYUWDfYeiizWo/llE7t0Iipy1RWHAKimpA3ZvA64KJiyI9/iu8PfxgH5BBmdbX8e/t9TJl25mQnzMIa1CxeY5CmwidkaZ40KWlXabuVXQaTVfFNXA9Xfbk3takN1awQFQELrNug9CBL0AdargcHv3Fw4ImbDwF+p3e5HCLCSuv3xQ5I/3E9pkittalWj3nJHUGwmLl/nB7+PxMpouNSL3Y1uu2JFgfW0BZmFZ3f7ehQVG4iRnTVE1I6722bgDakSgqszhxX/pOAXAM5XRfqEVO91k0NECAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAUmdLdiAkPJSFqXJWK2sT1hYT5fJy0OmnzkrbpQvR8y4zhA7xZKVzgFmd6lpP6HsNw14VPjH789IUfTbATvdQ1mLbnwD+J8IAPNpyzqqX8ie4jtecxhSQ+X1Da3UGI2ZpletwUJ77KnW5ow/NzM6kijRPWkIhUWpLBRuTkEysuriFdOhW73lUe4qmP2ehQ5YBtCGtCBAa6S1HQlJhwOexAf61QU0My+CXl10S1MDGJHKet5eTOhkI8lhxuYoGxHm3kTe3rF7aO4Rs9R30mOE+dqf4Nw8erbIUkxaLRtBC/gQqGuFZ989ps5HRR+6RTJnpyOifJs6QLyg71OkvON5jAVV1e3zs8eb8RXOp8C4bGJf7NBTQwzaxeZsYgQ9NNFCCtZSZldpeSl+HFMfIBbERAsUmItT86R0vMUJ07ia0zHIJDd9URu6fTEMCuCJy1FKzJy2tkV51llYO2y8crzdNn8po2LPBZF3whNNhueYIu4SqFSFUNQxJvFQ+LuyTHELWqYkPg2LIq+wgsvPabewjwKIBjVSNe09pFhQk2orlXmJmulS384p/uANdb4+9o7h4q9sl4XsVGE0znNemBaFQgMLy//5525K3PLFFdUXQMHj2cYg8XdBy4pb06xfMbXNmHIuQ7uNBI6bUStx9XZgM2IAqgXoq5SucQtVrlV0+ktU=\r\n-----END CERTIFICATE-----";

  // Decode input certificate
  const asn1 = asn1js.fromBER(PemConverter.decode(certificatePem)[0]);
  const certSimpl = new pkijs.Certificate({ schema: asn1.result });

  const cmsEnveloped = new pkijs.EnvelopedData();

  cmsEnveloped.addRecipientByCertificate(certSimpl, { oaepHashAlgorithm: oaepHashAlgo });

  await cmsEnveloped.encrypt({ name: encryptionAlgo, length: length }, Convert.FromUtf8String(text));

  const cmsContentSimpl = new pkijs.ContentInfo();
  cmsContentSimpl.contentType = "1.2.840.113549.1.7.3";
  cmsContentSimpl.content = cmsEnveloped.toSchema();

  const schema = cmsContentSimpl.toSchema();
  const ber = schema.toBER(false);

  // Insert enveloped data into new Mime message
  const mimeBuilder = new MimeNode("application/pkcs7-mime; name=smime.p7m; smime-type=enveloped-data; charset=binary")
    .setHeader("content-description", "Enveloped Data")
    .setHeader("content-disposition", "attachment; filename=smime.p7m")
    .setHeader("content-transfer-encoding", "base64")
    .setContent(new Uint8Array(ber));
  mimeBuilder.setHeader("from", "sender@example.com");
  mimeBuilder.setHeader("to", "recipient@example.com");
  mimeBuilder.setHeader("subject", "Example S/MIME encrypted message");

  return mimeBuilder.build();
}
/**
 * Adapted from PKI.js' SMIMEEncryptionExample
 * @returns {string} decrypted string
 * @param {string} text string to decrypt
 * @param {string} privateKeyPem user's private key to decrypt with in PEM format
 * @param {string} certificatePem user's public certificate to decrypt with in PEM format
 */
export async function smimeDecrypt(text: string, privateKeyPem: string, certificatePem: string): Promise<string> {
  //   text = `Content-Type: application/pkcs7-mime; name=smime.p7m;
  //  smime-type=enveloped-data; charset=binary
  // Content-Description: Enveloped Data
  // Content-Disposition: attachment; filename=smime.p7m
  // Content-Transfer-Encoding: base64
  // From: sender@example.com
  // To: recipient@example.com
  // Subject: Example S/MIME encrypted message
  // Date: Sat, 03 Jul 2021 19:02:11 +0000
  // Message-Id: <1625338931607-8158872e-ddc5c3d9-ca3c092d@example.com>
  // MIME-Version: 1.0

  // MIIDIAYJKoZIhvcNAQcDoIIDETCCAw0CAQIxggKyMIICrgIBADBnMGIxCzAJBgNVBAYTAlVTMREw
  // DwYDVQQIDAhWaXJnaW5pYTEQMA4GA1UEBwwHRmFpcmZheDEMMAoGA1UECgwDR01VMQwwCgYDVQQL
  // DANNU0wxEjAQBgNVBAMMCUpvc2ggWXVlbgIBATA8BgkqhkiG9w0BAQcwL6APMA0GCWCGSAFlAwQC
  // AQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUABIICAK4EjAp/MgvPToiEMUt8j+f3JrYy
  // km9U8fAG5q3O+cjHAToT38CKkoIOI3aMP5jWYBvrlz7hNxMLnUHdgDMOXmDU+k1atdrERhUGV+h2
  // BSw2rfDewECcxf1MB/yCjvblBoosCsG2OKemp/FqdB+PEbzWAaFTgaUgfB8hN1KmkunscYz1Bmq0
  // vnhtMSE+zFFTId0DPWEzf23rW4mYKauFSVImnVpz2HiUG13vTPb7Ao90iZip0Pw0ylm1j/tHKrrR
  // YzdRJyHweE5Vh5RzMpmpT5iUo74VoqelbDAEyAGrdcyFevepi5j1HL6IPRkJHRFTyec/WYGe9zKG
  // p5X+/Cphf+gBBp9eBzQxm09nmc12XyhiqKl7n7YfLJldlhBliSU1topyHpu8DfZ7xBmcSvgSFO82
  // e/YJMp6cW0oWx6fBEuvwXzQarcn/CR6MsXVQdRYCwNHI1viXGWs6EW5l9klX/UHUYe+417GRSiv4
  // H2wXfpG/fczHySKMPCAEA6dgKj/oojlVVS+3uTaLdhjinRNueN9SQD60xLXTsYVGL2T9AAOKWGS0
  // 4jIpE1SpBXFlpZfh3ZqCXhqGXFVEKbkHPzNv1760P9/7+AxmgqNploIsICcifkJWYPcBiq5VfUkf
  // 8IvWVpVl2p6JKXDNdvcyJECzP71y53laO4Us8TD+w6998UE/MIAGCSqGSIb3DQEHATAdBglghkgB
  // ZQMEAQIEEAbsXBSBD63kSzxi1vZzZIWggAQg2mpmlyaUHXnl94gxCBM1mG5ePJa6Ejpxynn5tL9u
  // /mYAAAAA`;

  certificatePem =
    "------BEGIN CERTIFICATE-----\r\nMIIFYjCCA0oCAQEwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMRAwDgYDVQQHDAdGYWlyZmF4MQwwCgYDVQQKDANHTVUxDDAKBgNVBAsMA01TTDESMBAGA1UEAwwJSm9zaCBZdWVuMB4XDTIxMDUxMTAxMDAxOFoXDTMxMDUwOTAxMDAxOFowgYsxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhWaXJnaW5pYTEQMA4GA1UEBwwHRmFpcmZheDEMMAoGA1UECgwDR01VMQwwCgYDVQQLDANNU0wxEjAQBgNVBAMMCUpvc2ggWXVlbjEnMCUGCSqGSIb3DQEJARYYanl1ZW4yQG1hc29ubGl2ZS5nbXUuZWR1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtqqoLT0P8O5f14ZR2NlhO8VWRQbxxi2k9eXmV1RdzRfH2qhp6cM0SFtZ3O1yjlWA1QSYlLOYJbOgYXO2HMVGWmCTY1UEQgJIcQRlmv9G8P5IcQCVmPPgJtZq1M8n3rHdnbZ0eOdoikWv3BCyc4myupsiuFtETGdcQp02M33S+9yJWo+I0D5d9juMX3uCHBkQnQdU4u/shzYRgct1jX1PlXHZsFzLP/KtfrpPcReP6MEpB/ySneMMN++tFnN0CX1DfM2zOBXgTfQS9/QirN9saQS2MQGaB/vayjV+ELirFnzKsO02VHh77T8hIXDgsu1bnSVv8PpDDPhBPtXCSin8Xo50P09rVus/wnnh1xUyR6tTYoDx6aZKwcuX0gLyB4Hl+6qvqh3xCuS8ikrmYUWDfYeiizWo/llE7t0Iipy1RWHAKimpA3ZvA64KJiyI9/iu8PfxgH5BBmdbX8e/t9TJl25mQnzMIa1CxeY5CmwidkaZ40KWlXabuVXQaTVfFNXA9Xfbk3takN1awQFQELrNug9CBL0AdargcHv3Fw4ImbDwF+p3e5HCLCSuv3xQ5I/3E9pkittalWj3nJHUGwmLl/nB7+PxMpouNSL3Y1uu2JFgfW0BZmFZ3f7ehQVG4iRnTVE1I6722bgDakSgqszhxX/pOAXAM5XRfqEVO91k0NECAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAUmdLdiAkPJSFqXJWK2sT1hYT5fJy0OmnzkrbpQvR8y4zhA7xZKVzgFmd6lpP6HsNw14VPjH789IUfTbATvdQ1mLbnwD+J8IAPNpyzqqX8ie4jtecxhSQ+X1Da3UGI2ZpletwUJ77KnW5ow/NzM6kijRPWkIhUWpLBRuTkEysuriFdOhW73lUe4qmP2ehQ5YBtCGtCBAa6S1HQlJhwOexAf61QU0My+CXl10S1MDGJHKet5eTOhkI8lhxuYoGxHm3kTe3rF7aO4Rs9R30mOE+dqf4Nw8erbIUkxaLRtBC/gQqGuFZ989ps5HRR+6RTJnpyOifJs6QLyg71OkvON5jAVV1e3zs8eb8RXOp8C4bGJf7NBTQwzaxeZsYgQ9NNFCCtZSZldpeSl+HFMfIBbERAsUmItT86R0vMUJ07ia0zHIJDd9URu6fTEMCuCJy1FKzJy2tkV51llYO2y8crzdNn8po2LPBZF3whNNhueYIu4SqFSFUNQxJvFQ+LuyTHELWqYkPg2LIq+wgsvPabewjwKIBjVSNe09pFhQk2orlXmJmulS384p/uANdb4+9o7h4q9sl4XsVGE0znNemBaFQgMLy//5525K3PLFFdUXQMHj2cYg8XdBy4pb06xfMbXNmHIuQ7uNBI6bUStx9XZgM2IAqgXoq5SucQtVrlV0+ktU=\r\n-----END CERTIFICATE-----";

  privateKeyPem =
    "-----BEGIN PRIVATE KEY-----\r\n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\r\n-----END PRIVATE KEY-----";

  // Decode input certificate
  let asn1 = asn1js.fromBER(PemConverter.decode(certificatePem)[0]);
  const certSimpl = new pkijs.Certificate({ schema: asn1.result });

  // Decode input private key
  const privateKeyBuffer = PemConverter.decode(privateKeyPem)[0];

  // Parse S/MIME message to get CMS enveloped content
  try {
    const parser = smimeParse(text);

    // Make all CMS data
    asn1 = asn1js.fromBER(parser.content.buffer);
    if (asn1.offset === -1) {
      alert('Unable to parse your data. Please check you have "Content-Type: charset=binary" in your S/MIME message');
      return;
    }

    const cmsContentSimpl = new pkijs.ContentInfo({ schema: asn1.result });
    const cmsEnvelopedSimpl = new pkijs.EnvelopedData({ schema: cmsContentSimpl.content });

    const message = await cmsEnvelopedSimpl.decrypt(0, {
      recipientCertificate: certSimpl,
      recipientPrivateKey: privateKeyBuffer,
    });

    return Convert.ToUtf8String(message);
  } catch (err) {
    // Not an S/MIME message
    throw err;
  }
}
