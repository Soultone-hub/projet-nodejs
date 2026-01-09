import prisma from "#lib/prisma.js";
import { hashPassword, verifyPassword } from "#lib/password.js";
import { generateAccessToken, generateRefreshToken } from "#lib/jwt.js"; // On va créer ces fonctions
import { UnauthorizedException, ConflictException } from "#lib/exceptions.js";

export class UserService {
  static async register(data) {
    const existingUser = await prisma.user.findUnique({ where: { email: data.email } });
if (existingUser) throw new Error("Cet email est déjà utilisé");
    const hashedPassword = await hashPassword(data.password);
    
    return prisma.user.create({
      data: {
        email: data.email,
        password: hashedPassword,
        name: data.name,
      },
      select: { id: true, email: true, name: true }
    });
  }

  static async login(email, password, ip, userAgent) {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await verifyPassword(user.password, password))) {
      throw new UnauthorizedException("Identifiants invalides");
    }

    // 1. Générer les tokens
    const accessToken = await generateAccessToken({ id: user.id });
    const refreshTokenString = await generateRefreshToken({ id: user.id });

    // 2. Enregistrer le Refresh Token en base (Gestion de Session)
    // Conformément au TP : Whitelist et stockage IP/Appareil
    await prisma.session.create({
  data: {
    refreshToken: refreshTokenString, // Le champ s'appelle refreshToken dans ton schéma
    userId: user.id,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    // Note : Ton modèle Session actuel n'a pas de champs IP/UserAgent. 
    // Si tu en as besoin pour le TP, vois l'étape 2 ci-dessous.
  }
});
  await prisma.loginHistory.create({
  data: {
    email: email,
    ip: ipAddress, // Tu devras passer l'IP depuis le contrôleur
    userAgent: userAgent, // Tu devras passer le UserAgent depuis le contrôleur
    success: true
  }
});
    return { accessToken, refreshToken: refreshTokenString, user: { id: user.id, email: user.email } };
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

}