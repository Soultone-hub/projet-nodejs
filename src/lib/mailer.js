import nodemailer from "nodemailer";

// DÉCISION : Déclaration du transporteur en haut du fichier
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export const sendVerificationEmail = async (to, token) => {
  const verificationLink = `http://localhost:3000/confirm-account?token=${token}`;
  
  const mailOptions = {
    from: `"Support Authentification" <${process.env.EMAIL_USER}>`,
    to: to,
    subject: "Activez votre compte",
    html: `
      <div style="font-family: sans-serif; border: 1px solid #eee; padding: 20px;">
        <h2>Bienvenue !</h2>
        <p>Cliquez sur le bouton ci-dessous pour valider votre inscription :</p>
        <a href="${verificationLink}" 
           style="display: inline-block; padding: 12px 24px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
           Vérifier mon compte
        </a>
        <p style="margin-top: 20px; font-size: 0.8em; color: #666;">
          Si le bouton ne fonctionne pas, copiez ce lien : <br> ${verificationLink}
        </p>
      </div>
    `,
  };

  // DÉCISION : Utilisation du transporter défini plus haut
  return await transporter.sendMail(mailOptions);
};