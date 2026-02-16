'use strict';

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const nodemailer = require('nodemailer');
const twilio = require('twilio');

const app = express();
app.use(helmet());
app.use(cors()); // pour dev, autoriser toutes origines
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 3000;

// Vérifier configuration SMTP
function getTransporter() {
  const host = process.env.SMTP_HOST;
  const port = parseInt(process.env.SMTP_PORT || '587', 10);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) return null;
  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465, // true for 465, false for other ports
    auth: { user, pass }
  });
}

app.post('/send-email', async (req, res) => {
  try {
    const { to, subject, message } = req.body || {};
    if (!Array.isArray(to) || to.length === 0) return res.status(400).json({ error: 'Paramètre "to" manquant ou invalide' });
    if (!subject || !message) return res.status(400).json({ error: 'Objet ou message manquant' });

    const transporter = getTransporter();
    if (!transporter) return res.status(500).json({ error: 'SMTP non configuré. Voir la documentation.' });

    const toList = to.filter(Boolean).join(',');

    // Default sender: prefer FROM_EMAIL, then SMTP_USER, then admin email fallback
    const defaultFrom = process.env.FROM_EMAIL || process.env.SMTP_USER || 'seydoubakhayokho1@gmail.com';

    const mailOptions = {
      from: defaultFrom,
      to: toList,
      subject: subject,
      text: message,
      html: message.replace(/\n/g, '<br>')
    };

    const info = await transporter.sendMail(mailOptions);
    return res.json({ ok: true, info });
  } catch (err) {
    console.error('send-email error', err);
    return res.status(500).json({ error: 'Erreur interne lors de l\'envoi' });
  }
});

// Endpoint pour envoi WhatsApp en groupe
app.post('/send-whatsapp', async (req, res) => {
  try {
    const { numbers, message } = req.body || {};
    if (!Array.isArray(numbers) || numbers.length === 0) return res.status(400).json({ error: 'Paramètre "numbers" manquant ou invalide' });
    if (!message) return res.status(400).json({ error: 'Message manquant' });

    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    const whatsappFrom = process.env.TWILIO_WHATSAPP_FROM; // format: '+1415XXXXXXX'

    if (accountSid && authToken && whatsappFrom) {
      const client = twilio(accountSid, authToken);
      const sendPromises = numbers.map(num => {
        const normalized = (num || '').replace(/[^0-9\+]/g, '');
        // Ensure number in E.164; if it starts with + keep it, otherwise assume it's full international
        const to = normalized.startsWith('+') ? 'whatsapp:' + normalized : 'whatsapp:+' + normalized;
        return client.messages.create({ from: 'whatsapp:' + whatsappFrom, to: to, body: message });
      });
      const results = await Promise.all(sendPromises);
      return res.json({ ok: true, sent: results.length, results: results.map(r => ({ sid: r.sid, to: r.to })) });
    }

    // Fallback: return wa.me links so client can open them manually
    const waLinks = numbers.map(n => {
      const normalized = (n || '').replace(/[^0-9]/g, '');
      return 'https://wa.me/' + normalized + '?text=' + encodeURIComponent(message);
    });
    return res.json({ ok: true, waLinks });
  } catch (err) {
    console.error('send-whatsapp error', err);
    return res.status(500).json({ error: 'Erreur interne lors de l\'envoi WhatsApp' });
  }
});

app.get('/', (req, res) => res.json({ ok: true, message: 'Email backend up' }));

app.listen(PORT, () => console.log(`Email backend running on http://localhost:${PORT}`));
