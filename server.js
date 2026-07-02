const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY || !process.env.BREVO_API_KEY) {
  console.error('Missing required environment variables. Please set SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, and BREVO_API_KEY.');
  process.exit(1);
}

const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    persistSession: false
  }
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '/')));

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePassword(password) {
  const re = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
  return re.test(password);
}

app.post('/api/auth/request-otp', async (req, res) => {
  try {
    const { email, password, fullName } = req.body;

    if (!email || !validateEmail(email)) {
      return res.status(400).json({ success: false, message: 'Valid email is required.' });
    }
    if (!password || !validatePassword(password)) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters, include uppercase, lowercase, and a number.' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    const { error: upsertError } = await supabaseAdmin.from('auth_otps').upsert([
      {
        email: email.toLowerCase(),
        otp: otp,
        expires_at: expiresAt,
        full_name: fullName || ''
      }
    ], { onConflict: ['email'] });

    if (upsertError) {
      console.error('Supabase OTP upsert error:', upsertError);
      return res.status(500).json({ success: false, message: 'Unable to save OTP.' });
    }

    const brevoResponse = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': process.env.BREVO_API_KEY
      },
      body: JSON.stringify({
        sender: {
          name: 'Busted Child',
          email: process.env.BREVO_SENDER_EMAIL || 'no-reply@bustedchild.co.za'
        },
        to: [{ email }],
        subject: 'Your Busted Child verification code',
        htmlContent: `<html><body><p>Hi,</p><p>Your verification code is <strong>${otp}</strong>.</p><p>Enter it in the Busted Child verification page to finish creating your account. This code expires in 15 minutes.</p><p>Thanks,<br />Busted Child</p></body></html>`
      })
    });

    if (!brevoResponse.ok) {
      const errBody = await brevoResponse.text();
      console.error('Brevo send failure:', brevoResponse.status, errBody);
      return res.status(500).json({ success: false, message: 'Failed to send OTP email.' });
    }

    return res.json({ success: true, message: 'OTP sent to your email.' });
  } catch (err) {
    console.error('request-otp error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !validateEmail(email)) {
      return res.status(400).json({ success: false, message: 'Valid email is required.' });
    }
    if (!otp || otp.length !== 6) {
      return res.status(400).json({ success: false, message: 'Valid OTP is required.' });
    }

    const { data, error } = await supabaseAdmin.from('auth_otps').select('*').eq('email', email.toLowerCase()).single();
    if (error) {
      console.error('Supabase OTP select error:', error);
      return res.status(500).json({ success: false, message: 'Unable to verify OTP.' });
    }
    if (!data) {
      return res.status(400).json({ success: false, message: 'OTP not found. Request a new one.' });
    }
    if (data.otp !== otp) {
      return res.status(400).json({ success: false, message: 'OTP is incorrect.' });
    }
    if (new Date(data.expires_at) < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP has expired. Request a new one.' });
    }
    if (!req.body.password) {
      return res.status(400).json({ success: false, message: 'Password is required to complete verification.' });
    }

    const createResult = await supabaseAdmin.auth.admin.createUser({
      email: email.toLowerCase(),
      password: req.body.password,
      user_metadata: {
        full_name: data.full_name || ''
      },
      email_confirm: true
    });

    if (createResult.error) {
      console.error('Supabase admin createUser error:', createResult.error);
      return res.status(500).json({ success: false, message: createResult.error.message || 'Unable to create the account.' });
    }

    const { error: deleteError } = await supabaseAdmin.from('auth_otps').delete().eq('email', email.toLowerCase());
    if (deleteError) {
      console.warn('Failed to delete used OTP record:', deleteError);
    }

    return res.json({ success: true, message: 'Account verified successfully. You can now sign in.' });
  } catch (err) {
    console.error('verify-otp error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !validateEmail(email)) {
      return res.status(400).json({ success: false, message: 'Valid email is required.' });
    }

    const { data, error } = await supabaseAdmin.from('auth_otps').select('*').eq('email', email.toLowerCase()).single();
    if (error) {
      console.error('Supabase OTP select error:', error);
      return res.status(500).json({ success: false, message: 'Unable to resend OTP.' });
    }
    if (!data) {
      return res.status(400).json({ success: false, message: 'No pending verification found. Request a new OTP.' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    const { error: updateError } = await supabaseAdmin.from('auth_otps').update({ otp, expires_at: expiresAt }).eq('email', email.toLowerCase());
    if (updateError) {
      console.error('Supabase OTP update error:', updateError);
      return res.status(500).json({ success: false, message: 'Unable to update OTP.' });
    }

    const brevoResponse = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': process.env.BREVO_API_KEY
      },
      body: JSON.stringify({
        sender: {
          name: 'Busted Child',
          email: process.env.BREVO_SENDER_EMAIL || 'no-reply@bustedchild.co.za'
        },
        to: [{ email }],
        subject: 'Your Busted Child verification code',
        htmlContent: `<html><body><p>Hi,</p><p>Your verification code is <strong>${otp}</strong>.</p><p>This code expires in 15 minutes.</p><p>Thanks,<br />Busted Child</p></body></html>`
      })
    });

    if (!brevoResponse.ok) {
      const errBody = await brevoResponse.text();
      console.error('Brevo resend failure:', brevoResponse.status, errBody);
      return res.status(500).json({ success: false, message: 'Failed to send OTP email.' });
    }

    return res.json({ success: true, message: 'OTP resent to your email.' });
  } catch (err) {
    console.error('resend-otp error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

app.listen(port, () => {
  console.log(`Auth server listening on port ${port}`);
});
