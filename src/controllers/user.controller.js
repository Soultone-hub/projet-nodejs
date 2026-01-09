import { UserService } from "#services/user.service.js";
import jwt from "jsonwebtoken";
export class UserController {
  // Cette méthode DOIT exister pour que le router la trouve
  static async register(req, res) {
    const user = await UserService.register(req.body);
    res.status(201).json({
      success: true,
      data: user
    });
  }

  // Ajoute aussi celle-ci pour ne pas avoir d'erreur sur la route /login
  static async login(req, res) {
  const { email, password } = req.body;
  const ip = req.ip || "127.0.0.1";
  const userAgent = req.headers["user-agent"] || "unknown";

  const result = await UserService.login(email, password, ip, userAgent);
  
  // Si le 2FA est requis, on adapte la réponse
  if (result.requires2FA) {
    return res.json({
      success: true,
      requires2FA: true,
      userId: result.userId,
      message: result.message
    });
  }

  res.json({
    success: true,
    data: result
  });
}

  static async getMe(req, res) {
  // req.user est rempli par le middleware userGuard
  const user = await UserService.getProfile(req.user.id);
  
  res.json({
    success: true,
    data: user
  });
}

// Dans user.controller.js
static async logout(req, res) {
  const { refreshToken } = req.body;
  const accessToken = req.headers.authorization?.split(" ")[1];

  // 1. Révoquer la session (Refresh Token)
  await UserService.logout(refreshToken);

  // 2. Blacklister l'Access Token actuel
  if (accessToken) {
    const decoded = jwt.decode(accessToken);
    await UserService.blacklistToken(accessToken, decoded.exp);
  }

  res.json({ success: true, message: "Déconnexion totale réussie" });
}

static async getSessions(req, res) {
  const sessions = await UserService.getActiveSessions(req.user.id);
  res.json({ success: true, sessions });
}

static async terminateSession(req, res) {
  const { sessionId } = req.params;
  await UserService.revokeSession(sessionId, req.user.id);
  res.json({ success: true, message: "Session révoquée avec succès" });
}

static async refreshToken(req, res) {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ success: false, message: "Refresh token manquant" });
  }

  try {
    const result = await UserService.refresh(refreshToken);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(401).json({ success: false, message: error.message });
  }
}

static async forgotPassword(req, res) {
  const { email } = req.body;
  const token = await UserService.requestPasswordReset(email);
  // On renvoie le token pour que tu puisses tester sans serveur SMTP
  res.json({ success: true, message: "Token de réinitialisation généré", token });
}

static async resetPassword(req, res) {
  const { token, newPassword } = req.body;
  await UserService.resetPassword(token, newPassword);
  res.json({ success: true, message: "Mot de passe modifié avec succès" });
}

static async oauthCallback(req, res) {
  const { provider, providerId, email, name } = req.body;

  if (!provider || !providerId || !email) {
    return res.status(400).json({ success: false, message: "Données OAuth incomplètes" });
  }

  const result = await UserService.loginWithOAuth(provider, providerId, email, name);
  res.json({ success: true, ...result });
}
static async setup2FA(req, res) {
  const result = await UserService.generate2FASecret(req.user.id);
  res.json({ success: true, ...result });
}

static async activate2FA(req, res) {
  const { code } = req.body;
  await UserService.verifyAndEnable2FA(req.user.id, code);
  res.json({ success: true, message: "2FA activé avec succès" });
}

static async verify2FALogin(req, res) {
  const { userId, code } = req.body;
  const result = await UserService.loginStep2FA(userId, code);
  res.json({ success: true, ...result });
}

static async terminateOtherSessions(req, res) {
  const { refreshToken } = req.body; // Le token actuel pour ne pas s'auto-déconnecter
  await UserService.revokeAllOtherSessions(req.user.id, refreshToken);
  res.json({ success: true, message: "Toutes les autres sessions ont été révoquées" });
}

static async updateMe(req, res) {
  const user = await UserService.updateProfile(req.user.id, req.body);
  res.json({ success: true, user });
}

static async deleteMe(req, res) {
  await UserService.deleteAccount(req.user.id);
  res.json({ success: true, message: "Compte supprimé définitivement" });
}

static async deactivate2FA(req, res) {
  await UserService.disable2FA(req.user.id);
  res.json({ success: true, message: "2FA désactivé" });
}

static async resendEmail(req, res) {
  const { email } = req.body;
  await UserService.resendVerification(email);
  res.json({ success: true, message: "Email de vérification renvoyé" });
}
static async verifyMe(req, res) {
  // On utilise la méthode déjà présente dans ton service
  const user = await UserService.verifyEmail(req.user.id);
  res.json({ success: true, message: "Email marqué comme vérifié !", data: user });
}
static async verifyMe(req, res) {
  // req.user.id est récupéré grâce au middleware userGuard
  const user = await UserService.verifyEmail(req.user.id);
  
  res.json({ 
    success: true, 
    message: "Votre email a été vérifié avec succès !",
    data: {
      email: user.email,
      verifiedAt: user.emailVerifiedAt
    }
  });
}
static async confirmAccount(req, res) {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ success: false, error: "Le jeton est requis." });
  }

  try {
    await UserService.verifyAccountByToken(token);
    res.json({ success: true, message: "Compte activé avec succès !" });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
}
static async resendConfirmation(req, res) {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: "L'email est requis" });
  }

  try {
    const data = await UserService.resendVerificationToken(email);
    res.json({ 
      success: true, 
      message: "Un nouveau jeton a été généré",
      token: data.verificationToken // Pour tes tests Yaak
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
}
static async disable2FA(req, res) {
  try {
    await UserService.disable2FA(req.user.id);
    res.json({ 
      success: true, 
      message: "La double authentification a été désactivée avec succès." 
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
}
static async deleteMe(req, res) {
  try {
    await UserService.deleteAccount(req.user.id);
    
    // Décision : On pourrait ici invalider le token actuel en le mettant en blacklist
    // mais la suppression du user suffit à bloquer les prochains refresh.
    
    res.json({ 
      success: true, 
      message: "Votre compte et toutes vos données associées ont été supprimés." 
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
}
}