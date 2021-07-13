/**
 * @jest-environment jsdom
 */

import "./setupTests";

import { smimeSign, smimeVerify } from "../helpers/emailFunctions";
import { decodeHtml, encodeHtml } from "../helpers/converters";

// Import the same cert and key used within the add-in
import { cert, key } from "./certAndKey";

const plaintext = "This is some plaintext.";

test("sign and verify some plaintext", async () => {
  const signedText = await smimeSign(plaintext, key, cert);
  console.log(signedText);
  const ok = await smimeVerify(signedText, cert);
  console.log(ok);
expect(ok.signatureVerified).toBe(true);
});

/*
// The below tests exist since we surround S/MIME text with <pre> tags to prevent Outlook from inserting its own HTML tags within the S/MIME message and messing with the message integrity when setting the message body.
test("encrypt and decrypt some plaintext with <pre> tags surrounding", async () => {
  const signedText = await smimeEncrypt(plaintext, cert);
  const signedTextBody = "<pre>" + signedText + "</pre>";

  // Escape HTML encoded strings
  let originalEmailBody = decodeHtml(signedTextBody);

  // Remove <div>'s
  originalEmailBody = originalEmailBody.replace(/<div>/g, "");

  // Remove </div>'s
  originalEmailBody = originalEmailBody.replace(/<\/div>/g, "");

  // Remove <span>'s
  originalEmailBody = originalEmailBody.replace(/<span>/g, "");

  // Remove </span>'s
  originalEmailBody = originalEmailBody.replace(/<\/span>/g, "");

  // Replace <br>'s with \r\n
  originalEmailBody = originalEmailBody.replace(/<br>/g, "\r\n");

  // Remove <pre>'s
  originalEmailBody = originalEmailBody.replace(/<pre>/g, "");

  // Remove </pre>'s
  originalEmailBody = originalEmailBody.replace(/<\/pre>/g, "");

  // Detect S/MIME section
  let smimeSection = originalEmailBody.substring(originalEmailBody.indexOf("Content-Type:"));

  const ok = await smimeVerify(smimeSection);
  expect(ok.signatureVerified).toBe(true);
});

test("encrypt and decrypt text surrounded by <span> and <pre> tags", async () => {
  const signedText = await smimeEncrypt(plaintext, cert);
  const signedTextPre = "<pre>" + signedText + "</pre>";
  const signedTextSpanPre = "<pre>" + signedTextPre + "</span>";

  // Escape HTML encoded strings
  let originalEmailBody = decodeHtml(signedTextSpanPre);

  // Remove <div>'s
  originalEmailBody = originalEmailBody.replace(/<div>/g, "");

  // Remove </div>'s
  originalEmailBody = originalEmailBody.replace(/<\/div>/g, "");

  // Remove <span>'s
  originalEmailBody = originalEmailBody.replace(/<span>/g, "");

  // Remove </span>'s
  originalEmailBody = originalEmailBody.replace(/<\/span>/g, "");

  // Replace <br>'s with \r\n
  originalEmailBody = originalEmailBody.replace(/<br>/g, "\r\n");

  // Remove <pre>'s
  originalEmailBody = originalEmailBody.replace(/<pre>/g, "");

  // Remove </pre>'s
  originalEmailBody = originalEmailBody.replace(/<\/pre>/g, "");

  // Detect S/MIME section
  let smimeSection = originalEmailBody.substring(originalEmailBody.indexOf("Content-Type:"));

  const ok = await smimeDecrypt(smimeSection, key, cert);
  expect(ok).toBe(plaintext);
});

// Outlook HTML encodes
test("encrypt and decrypt text surrounded by <span> and <pre> tags that has been HTML encoded", async () => {
  const signedText = await smimeEncrypt(plaintext, cert);
  // console.log(signedText);
  const signedTextHtmlEncoded = encodeHtml(signedText);
  // console.log(signedTextHtmlEncoded);
  const signedTextPre = "<pre>" + signedTextHtmlEncoded + "</pre>";
  // console.log(signedTextPre);
  const signedTextSpanPre = "<span>" + signedTextPre + "</span>";
  // console.log(signedTextSpanPre);

  // Escape HTML encoded strings
  let originalEmailBody = decodeHtml(signedTextSpanPre);
  // let originalEmailBody = decodeHtml(signedTextSpanPre);

  // Remove <div>'s
  originalEmailBody = originalEmailBody.replace(/<div>/g, "");

  // Remove </div>'s
  originalEmailBody = originalEmailBody.replace(/<\/div>/g, "");

  // Remove <span>'s
  originalEmailBody = originalEmailBody.replace(/<span>/g, "");

  // Remove </span>'s
  originalEmailBody = originalEmailBody.replace(/<\/span>/g, "");

  // Replace <br>'s with \r\n
  originalEmailBody = originalEmailBody.replace(/<br>/g, "\r\n");

  // Remove <pre>'s
  originalEmailBody = originalEmailBody.replace(/<pre>/g, "");

  // Remove </pre>'s
  originalEmailBody = originalEmailBody.replace(/<\/pre>/g, "");

  // Detect S/MIME section
  let smimeSection = originalEmailBody.substring(originalEmailBody.indexOf("Content-Type:"));

  const ok = await smimeDecrypt(smimeSection, key, cert);
  // console.log(ok)
  expect(ok).toBe(plaintext);
});
*/