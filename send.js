import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses"

async function verifySignature(secret, data, receivedSignature) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(data)
  );

  const base64Signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
  
  return base64Signature === receivedSignature;
}

export async function onRequestPost(context) {
  const env = context.env;
  const bodyText = await context.request.text();
  const { data } = JSON.parse(bodyText);

  const receivedSignature = context.request.headers.get("tally-signature");

  const isValidSignature = await verifySignature(env.TALLY_SIGNING_SECRET, bodyText, receivedSignature);

  if (!isValidSignature) {
    console.error("Invalid signature.");
    return new Response(null, {
      status: 401,
    });
  }

  // Signature is valid, proceed to send email
  const emailSubject = `New Feedback`;
  const emailBodyText = `You received new feedback. Go to dashboard: https://tally.so/forms/nGLBXQ/submissions.\n\n`;
  const emailBodyHtml = `<p>You received new feedback. <a href="https://tally.so/forms/nGLBXQ/submissions">Go to dashboard</a></p>`;

  const fieldsText = data.fields
    .map((field) => `${field.label}: ${field.value}`)
    .join("\n");
  const fieldsHtml = data.fields
    .map((field) => `<p><strong>${field.label}:</strong><br>${field.value}</p>`)
    .join("");

  const client = new SESClient({
    region: "eu-north-1",
    credentials: {
      accessKeyId: env.AWS_ACCESS_KEY_ID,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
    },
  });

  const params = {
    Source: "Feedback notification <feedback@polrivero.com>",
    Destination: {
      ToAddresses: env.TO_ADDRESSES_COMMA_SEPARATED.split(","),
    },
    Message: {
      Subject: {
        Charset: "UTF-8",
        Data: emailSubject,
      },
      Body: {
        Text: {
          Charset: "UTF-8",
          Data: emailBodyText + fieldsText,
        },
        Html: {
          Charset: "UTF-8",
          Data: emailBodyHtml + fieldsHtml,
        },
      },
    },
  };

  try {
    const command = new SendEmailCommand(params);
    await client.send(command);
    console.log("Email sent successfully!");
    return new Response(null, {
      status: 200,
    });
  } catch (error) {
    console.error("Error sending email: ", error);
    return new Response(null, {
      status: 500,
    });
  }
}
