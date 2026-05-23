import nodemailer from 'nodemailer';

let transport;

function getTransport() {
  if (!transport) {
    transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT) || 587,
      secure: Number(process.env.SMTP_PORT) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }
  return transport;
}

function devLog(label, to, extra = '') {
  console.log(`[mailer:dev] ${label} → ${to}${extra}`);
}

export async function sendOtpEmail(to, otp) {
  if (!process.env.SMTP_HOST) {
    devLog('OTP', to, `  code: ${otp}`);
    return;
  }
  await getTransport().sendMail({
    from: process.env.SMTP_FROM || 'noreply@secmail.app',
    to,
    subject: 'Your SecMail verification code',
    text: `Your SecMail verification code is: ${otp}\n\nThis code expires in 10 minutes. Do not share it with anyone.`,
  });
}

export async function sendRevocationAlert(to, keyId) {
  if (!process.env.SMTP_HOST) {
    devLog('revocation alert', to, `  keyId: ${keyId}`);
    return;
  }
  await getTransport().sendMail({
    from: process.env.SMTP_FROM || 'noreply@secmail.app',
    to,
    subject: 'SecMail: key revocation requested',
    text: [
      `A revocation was requested for your SecMail key (${keyId}).`,
      '',
      'You have 24 hours to cancel this if you did not request it.',
      `Cancel at: ${process.env.SERVER_BASE_URL || 'https://your-server.com'}/auth/bootstrap/cancel-revocation`,
      '',
      'If you did not request this revocation, act immediately.',
    ].join('\n'),
  });
}

export async function sendDeletionAlert(to, keyId, recoverableUntil) {
  if (!process.env.SMTP_HOST) {
    devLog('deletion alert', to, `  keyId: ${keyId}`);
    return;
  }
  await getTransport().sendMail({
    from: process.env.SMTP_FROM || 'noreply@secmail.app',
    to,
    subject: 'SecMail: key deleted',
    text: [
      `Your SecMail key (${keyId}) has been deleted.`,
      '',
      `You can recover it within 6 months (until ${recoverableUntil.toUTCString()}) using the key recovery feature in the SecMail app.`,
    ].join('\n'),
  });
}
