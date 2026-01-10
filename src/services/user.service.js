import bcrypt from "bcrypt";
import crypto from "crypto";
import { randomBytes } from "crypto";
import { authenticator } from 'otplib';
import prisma from "#lib/prisma.js";
import { sendVerificationEmail } from "../lib/mailer.js";
import { PrismaClient } from "@prisma/client";
import { hashPassword, verifyPassword } from "#lib/password.js";
import { generateAccessToken, generateRefreshToken } from "#lib/jwt.js"; // On va créer ces fonctions
import { UnauthorizedException, ConflictException } from "#lib/exceptions.js";

export class UserService {
  static async register(data) {
  const existingUser = await prisma.user.findUnique({ where: { email: data.email } });
  if (existingUser) throw new Error("Cet email est déjà utilisé");

  const hashedPassword = await bcrypt.hash(data.password, 10);
  
  // Génération du jeton de vérification
  const token = randomBytes(32).toString('hex');

  const user = await prisma.user.create({
    data: {
      email: data.email,
      password: hashedPassword,
      name: data.name,
      verificationToken: token,
    }
  });

  // DÉCISION : Envoi réel du mail ici
  await sendVerificationEmail(user.email, token);

  return user;

  

}
 static async login(email, password, ip, userAgent) {
  // --- 1. PROTECTION BRUTE-FORCE ---
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
  const failedAttempts = await prisma.loginHistory.count({
    where: {
      email,
      success: false,
      createdAt: { gte: fiveMinutesAgo }
    }
  });

  if (failedAttempts >= 5) {
    throw new Error("Trop de tentatives échouées. Compte bloqué temporairement (5 min).");
  }

  // --- 2. VÉRIFICATION DES IDENTIFIANTS ---
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    await prisma.loginHistory.create({
      data: { email, ip, userAgent, success: false }
    });
    throw new Error("Identifiants invalides");
  }

  // --- 3. ENREGISTREMENT DU SUCCÈS ---
  await prisma.loginHistory.create({
    data: { email, ip, userAgent, success: true }
  });

  // --- 4. INTERCEPTION SI 2FA ACTIVÉ ---
  if (user.isTwoFactorEnabled) {
    // On ne génère PAS de tokens ici. L'utilisateur doit d'abord valider son code.
    return { 
      requires2FA: true, 
      userId: user.id, 
      message: "Veuillez fournir votre code de double authentification." 
    };
  }

  // --- 5. GÉNÉRATION DES TOKENS (Si pas de 2FA) ---
  const accessToken = await generateAccessToken({ id: user.id, role: user.role });
  const refreshToken = await generateRefreshToken({ id: user.id });

  await prisma.session.create({
    data: {
      userId: user.id,
      refreshToken,
      ip,
      userAgent,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    }
  });

  return { accessToken, refreshToken, user };
}
  static async getProfile(userId) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      emailVerifiedAt: true,
      twoFactorEnabledAt: true,
      createdAt: true
    }
  });

  if (!user) throw new Error("Utilisateur non trouvé");
  return user;
}

static async logout(refreshToken) {
  const session = await prisma.session.findUnique({
    where: { refreshToken }
  });

  if (!session) {
    throw new Error("Session non trouvée");
  }

  // On ne supprime pas, on révoque (comme demandé dans ton modèle)
  return await prisma.session.update({
    where: { refreshToken },
    data: { revokedAt: new Date() }
  });
}

static async getActiveSessions(userId) {
  return await prisma.session.findMany({
    where: {
      userId: userId,
      revokedAt: null, // On ne prend que les sessions valides
      expiresAt: { gt: new Date() } // Et non expirées
    },
    orderBy: { createdAt: 'desc' }
  });
}

// Révoquer une session spécifique par son ID
static async revokeSession(sessionId, userId) {
  return await prisma.session.updateMany({
    where: {
      id: sessionId,
      userId: userId // Sécurité : on vérifie que la session appartient bien au user
    },
    data: { revokedAt: new Date() }
  });
}
static async refresh(token) {
  // 1. Vérifier si la session existe et n'est pas révoquée
  const session = await prisma.session.findUnique({
    where: { refreshToken: token },
    include: { user: true }
  });

  if (!session || session.revokedAt || session.expiresAt < new Date()) {
    throw new Error("Session invalide ou expirée");
  }

  // 2. Générer un nouvel Access Token
  const accessToken = await generateAccessToken({ 
    id: session.user.id, 
    role: session.user.role 
  });

  return { accessToken };
}

static async requestPasswordReset(email) {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("Utilisateur non trouvé");

  // On crée un token unique de 32 caractères
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 3600000); // Expire dans 1h

  // On enregistre le token en base
  await prisma.passwordResetToken.create({
    data: { email, token, expiresAt }
  });

  // Pour le TP, on retourne le token (normalement on l'envoie par email)
  return token;
}

// Étape 2 : Réinitialiser avec le token
static async resetPassword(token, newPassword) {
  const resetRecord = await prisma.passwordResetToken.findUnique({
    where: { token }
  });

  if (!resetRecord || resetRecord.expiresAt < new Date()) {
    throw new Error("Token invalide ou expiré");
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  // Transaction : on met à jour le user ET on supprime le token utilisé
  await prisma.$transaction([
    prisma.user.update({
      where: { email: resetRecord.email },
      data: { password: hashedPassword }
    }),
    prisma.passwordResetToken.delete({ where: { token } })
  ]);

  return true;
}

static async blacklistToken(token, expiresAt) {
  return await prisma.blacklistedAccessToken.create({
    data: {
      token: token,
      expiresAt: new Date(expiresAt * 1000) // Conversion du timestamp JWT en Date
    }
  });
}

static async loginWithOAuth(provider, providerId, email, name) {
  // 1. Chercher si ce compte OAuth existe déjà
  // Note: Prisma transforme souvent OAuthAccount en oAuthAccount ou oauthAccount
  let account = await prisma.oAuthAccount.findUnique({
    where: {
      provider_providerId: { provider, providerId }
    },
    include: { user: true }
  });

  let user;

  if (account) {
    user = account.user;
  } else {
    // 2. Chercher par email si le compte n'est pas lié
    user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      // 3. Créer l'utilisateur si inexistant
      user = await prisma.user.create({
        data: {
          email,
          name,
          emailVerifiedAt: new Date(),
          password: null 
        }
      });
    }

    // 4. Lier le compte (Correction de la ligne 236)
    await prisma.oAuthAccount.create({
      data: {
        provider,
        providerId,
        userId: user.id
      }
    });
  }

  // 5. Génération des tokens
  const accessToken = await generateAccessToken({ id: user.id, role: user.role });
  const refreshToken = await generateRefreshToken({ id: user.id });

  return { accessToken, refreshToken, user };
}

static async generate2FASecret(userId) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  const secret = authenticator.generateSecret();
  
  // On génère une URL que l'utilisateur pourra scanner avec son app
  const otpauth = authenticator.keyuri(user.email, 'MonAppTP', secret);

  // On stocke temporairement le secret (ne pas activer isTwoFactorEnabled encore)
  await prisma.user.update({
    where: { id: userId },
    data: { twoFactorSecret: secret }
  });

  return { secret, otpauth };
}

// Étape 2 : Vérifier le premier code et activer définitivement le 2FA
static async verifyAndEnable2FA(userId, code) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  
  const isValid = authenticator.check(code, user.twoFactorSecret);
  
  if (!isValid) throw new Error("Code 2FA invalide");

  return await prisma.user.update({
    where: { id: userId },
    data: { 
      isTwoFactorEnabled: true,
      twoFactorEnabledAt: new Date()
    }
  });
}
// Désactivation du 2FA


// Renvoi de l'email de vérification (Simulé)
static async resendVerification(email) {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("Utilisateur non trouvé");
  // Dans un vrai projet, on générerait un nouveau VerificationToken ici
  return { message: "Email de vérification renvoyé (simulé)" };
}
// --- GESTION DES SESSIONS ---
static async revokeAllOtherSessions(userId, currentRefreshToken) {
  return await prisma.session.updateMany({
    where: {
      userId: userId,
      refreshToken: { not: currentRefreshToken }, // On garde la session en cours
      revokedAt: null
    },
    data: { revokedAt: new Date() }
  });
}

// --- GESTION DU PROFIL ---
static async updateProfile(userId, data) {
  return await prisma.user.update({
    where: { id: userId },
    data: { name: data.name }
  });
}

static async deleteAccount(userId) {
  return await prisma.$transaction([
    prisma.session.deleteMany({ where: { userId } }),
    prisma.user.delete({ where: { id: userId } })
  ]);
}

// --- SÉCURITÉ & 2FA ---
static async disable2FA(userId) {
  return await prisma.user.update({
    where: { id: userId },
    data: { 
      isTwoFactorEnabled: false, 
      twoFactorSecret: null,
      twoFactorEnabledAt: null 
    }
  });
}

// Valider le code 2FA lors d'une connexion (Step 2)
static async loginStep2FA(userId, code) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  
  if (!user || !user.twoFactorSecret) {
    throw new Error("Configuration 2FA introuvable");
  }

  const isValid = authenticator.check(code, user.twoFactorSecret);
  
  if (!isValid) throw new Error("Code 2FA invalide");

  // Si le code est bon, on génère enfin les tokens d'accès
  const accessToken = await generateAccessToken({ id: user.id, role: user.role });
  const refreshToken = await generateRefreshToken({ id: user.id });

  // On crée la session
  await prisma.session.create({
    data: {
      userId: user.id,
      refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    }
  });

  return { accessToken, refreshToken, user };
}
static async verifyEmail(userId) {
  // On cherche l'utilisateur
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new Error("Utilisateur non trouvé");

  // On met à jour la date de vérification
  return await prisma.user.update({
    where: { id: userId },
    data: { 
      emailVerifiedAt: new Date() 
    }
  });
}


static async generateVerificationToken(userId) {
  const token = randomBytes(32).toString('hex');
  await prisma.user.update({
    where: { id: userId },
    data: { verificationToken: token }
  });
  return token;
}

static async confirmAccount(token) {
  // 1. Chercher l'utilisateur avec ce jeton
  const user = await prisma.user.findFirst({
    where: { verificationToken: token }
  });

  // 2. Si aucun utilisateur n'est trouvé, le jeton est invalide ou déjà utilisé
  if (!user) {
    throw new Error("Jeton de vérification invalide ou expiré.");
  }

  // 3. Mettre à jour l'utilisateur : on valide l'email et on vide le jeton
  return await prisma.user.update({
    where: { id: user.id },
    data: {
      emailVerifiedAt: new Date(),
      verificationToken: null // Très important pour la sécurité
    }
  });
}

static async resendConfirmation(email) {
  // 1. Chercher l'utilisateur
  const user = await prisma.user.findUnique({ where: { email } });

  // 2. Vérifications de sécurité
  if (!user) throw new Error("Utilisateur non trouvé");
  if (user.emailVerifiedAt) throw new Error("Ce compte est déjà vérifié");

  // 3. Générer un nouveau jeton
  const newToken = randomBytes(32).toString('hex');

  // 4. Mettre à jour l'utilisateur
  await prisma.user.update({
    where: { id: user.id },
    data: { verificationToken: newToken }
  });

  // 5. Envoyer le nouvel email
  await sendVerificationEmail(user.email, newToken);

  return { message: "Nouvel email de vérification envoyé" };
}
static async disable2FA(userId) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new Error("Utilisateur non trouvé");

  // DÉCISION : Utilisation des noms exacts du schéma (isTwoFactorEnabled)
  return await prisma.user.update({
    where: { id: userId },
    data: { 
      twoFactorSecret: null,           // Supprime le secret
      isTwoFactorEnabled: false,      // Décision : nom corrigé ici
      twoFactorEnabledAt: null        // Optionnel : on remet aussi la date à null
    }
  });
}
static async deleteAccount(userId) {
  // 1. Récupérer l'utilisateur pour obtenir son email
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new Error("Utilisateur non trouvé");

  // DÉCISION : Utilisation des bons champs (email pour LoginHistory, userId pour le reste)
  return await prisma.$transaction([
    prisma.session.deleteMany({ where: { userId: userId } }),
    prisma.oAuthAccount.deleteMany({ where: { userId: userId } }),
    prisma.loginHistory.deleteMany({ where: { email: user.email } }), // Corrigé ici
    prisma.user.delete({ where: { id: userId } })
  ]);
}
}