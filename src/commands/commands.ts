/*
 * Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
 * See LICENSE in the project root for license information.
 */

/* global global, Office, self, window */

import { smimeSign, smimeVerify } from "../helpers/emailFunctions";
import { decodeHtml } from "../helpers/converters";

// Import the same cert and key used in the unit tests
import { cert, key } from "../tests/certAndKey";

Office.onReady(() => {
  // If needed, Office.js is ready to be called
});

async function sign(event: Office.AddinCommands.Event) {
  const signingMessage: Office.NotificationMessageDetails = {
    type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
    message: "Signing email...",
    icon: "Icon.80x80",
    persistent: true,
  };

  // Show a notification message
  Office.context.mailbox.item.notificationMessages.replaceAsync("sign", signingMessage);

  // Get email body
  Office.context.mailbox.item.body.getAsync(Office.CoercionType.Text, async (result) => {
    if (result.status !== Office.AsyncResultStatus.Succeeded) {
      console.error(`Action failed with message ${result.error.message}`);
      return;
    }
    let emailBody = result.value;

    let signedText = await smimeSign(emailBody, key, cert);

    console.log(signedText);

    // Uncomment this to show that decrypting the output directly from smimeEncrypt() still doesn't work for some reason
    // when being called from the Outlook add-in (compared to working properly from the unit tests)
    // "npm run testWindows" or "npm run testMac" to run the unit tests on the appropriate platform
    /*
    await smimeDecrypt(encryptedText, key, cert).then((decryptedText) => {
        console.log(decryptedText);
    }).catch((err) => {
        // Problem decrypting
        console.error("Couldn't decrypt email. (Not an S/MIME message?)", err);
        return;
    });
    */

    // Envelope encryptedText with <pre> tags to prevent Outlook from injecting HTML tags of their own and messing with message integrity
    let signedEmailBody = "<pre>" + signedText + "</pre>";

    // Set message body
    Office.context.mailbox.item.body.setAsync(signedEmailBody, { coercionType: Office.CoercionType.Html }, () => {
      const signSuccessMessage: Office.NotificationMessageDetails = {
        type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
        message: "Email successfully signed!",
        icon: "Icon.80x80",
        persistent: true,
      };

      // Show a notification message
      Office.context.mailbox.item.notificationMessages.replaceAsync("sign", signSuccessMessage);

      // Be sure to indicate when the add-in command function is complete
      event.completed();
    });
  });
}

/**
 * Shows a notification when the add-in command is executed.
 * @param event
 */
function action(event: Office.AddinCommands.Event) {
  const message: Office.NotificationMessageDetails = {
    type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
    message: "Performed action.",
    icon: "Icon.80x80",
    persistent: true,
  };

  // Show a notification message
  Office.context.mailbox.item.notificationMessages.replaceAsync("action", message);

  // Be sure to indicate when the add-in command function is complete
  event.completed();
}

async function verify(event: Office.AddinCommands.Event) {
  const verifyingMessage: Office.NotificationMessageDetails = {
    type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
    message: "Verifying email signature...",
    icon: "Icon.80x80",
    persistent: true,
  };

  // Show a notification message
  Office.context.mailbox.item.notificationMessages.replaceAsync("verify", verifyingMessage);

  Office.context.mailbox.item.body.getAsync(Office.CoercionType.Html, async (result) => {
    if (result.status !== Office.AsyncResultStatus.Succeeded) {
      console.error(`Action failed with message ${result.error.message}`);
      return;
    }

    let emailBody = result.value;

    // Escape HTML encoded strings
    emailBody = decodeHtml(emailBody);

    // Remove <div>'s
    emailBody = emailBody.replace(/<div>/g, "");

    // Remove </div>'s
    emailBody = emailBody.replace(/<\/div>/g, "");

    // Remove <span>'s
    emailBody = emailBody.replace(/<span>/g, "");

    // Remove </span>'s
    emailBody = emailBody.replace(/<\/span>/g, "");

    // Re,pve <br>'s
    emailBody = emailBody.replace(/<br>/g, "");

    // Replace <pre>'s
    emailBody = emailBody.replace(/<pre>/g, "");

    // Replace </pre>'s
    emailBody = emailBody.replace(/<\/pre>/g, "");

    // TODO: S/MIME section detection
    let smimeSection = emailBody.substring(emailBody.indexOf("Content-Type:"));

    await smimeVerify(smimeSection, cert)
      .then((ok) => {
        // couldn't verify properly
        if (ok === null || ok === undefined) {
          console.log("couldn't verify properly");
          return;
        }

        console.log(ok.signatureVerified);

        const verifySuccessMessage: Office.NotificationMessageDetails = {
          type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
          message: "Email signature successfully verified!",
          icon: "Icon.80x80",
          persistent: true,
        };

        // Show a notification message
        Office.context.mailbox.item.notificationMessages.replaceAsync("verify", verifySuccessMessage);

        // Be sure to indicate when the add-in command function is complete
        event.completed();

        // // Set message body
        // Office.context.mailbox.item.body.setAsync(ok, { coercionType: Office.CoercionType.Html }, () => {
        //   // Be sure to indicate when the add-in command function is complete
        //   event.completed();
        // });
      })
      .catch((err) => {
        // Problem decrypting
        console.error("Couldn't verify email. (Not an S/MIME message?)", err);

        const errorMessage: Office.NotificationMessageDetails = {
          type: Office.MailboxEnums.ItemNotificationMessageType.ErrorMessage,
          message: "Error verifying email. Not an S/MIME message? Check console for more details.",
        };

        // Show a notification message
        Office.context.mailbox.item.notificationMessages.replaceAsync("verify", errorMessage);

        // Be sure to indicate when the add-in command function is complete
        event.completed();
        return;
      });
  });
}

function getGlobal() {
  return typeof self !== "undefined"
    ? self
    : typeof window !== "undefined"
    ? window
    : typeof global !== "undefined"
    ? global
    : undefined;
}

const g = getGlobal() as any;

// The add-in command functions need to be available in global scope
g.sign = sign;
g.verify = verify;
