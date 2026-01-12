import { Router } from "express";
import passport from 'passport';
import { UserController } from "#controllers/user.controller.js";
import { asyncHandler } from "#lib/async-handler.js";
import { userGuard } from "#middlewares/guard.middleware.js";
import { UserService } from '../services/user.service.js';
import { checkBlacklist } from "#middlewares/auth.middleware.js";
import { TokenService } from '#services/token.service.js';

const router = Router();

// --- AUTHENTIFICATION ---
router.post("/register", asyncHandler(UserController.register));
router.post("/login", asyncHandler(UserController.login));
router.post("/refresh", asyncHandler(UserController.refreshToken));
router.post("/logout", checkBlacklist, userGuard, asyncHandler(UserController.logout));
router.post("/oauth/callback", asyncHandler(UserController.oauthCallback));

// --- SÉCURITÉ (2FA & PASSWORD) ---
router.post("/forgot-password", asyncHandler(UserController.forgotPassword));
router.post("/reset-password", asyncHandler(UserController.resetPassword));
router.post("/change-password", checkBlacklist, userGuard, asyncHandler(UserController.changePassword));

router.get("/2fa/setup", checkBlacklist, userGuard, asyncHandler(UserController.setup2FA));
router.post("/2fa/activate", checkBlacklist, userGuard, asyncHandler(UserController.activate2FA));
router.post("/2fa/disable", checkBlacklist, userGuard, asyncHandler(UserController.deactivate2FA));
router.post("/login/2fa", asyncHandler(UserController.verify2FALogin));

// --- VÉRIFICATION EMAIL ---
router.post("/verify-email", checkBlacklist, userGuard, asyncHandler(UserController.verifyMe));
router.post("/verify-email/resend", asyncHandler(UserController.resendEmail));

// --- PROFIL ---
router.get("/me", checkBlacklist, userGuard, asyncHandler(UserController.getMe));
router.patch("/me", checkBlacklist, userGuard, asyncHandler(UserController.updateMe));
router.delete("/me", checkBlacklist, userGuard, asyncHandler(UserController.deleteMe));

// --- SESSIONS ---
router.get("/sessions", checkBlacklist, userGuard, asyncHandler(UserController.getSessions));
router.delete("/sessions/:sessionId", checkBlacklist, userGuard, asyncHandler(UserController.terminateSession));
router.delete("/sessions-others", checkBlacklist, userGuard, asyncHandler(UserController.terminateOtherSessions));
router.get("/confirm-account", asyncHandler(UserController.confirmAccountFromLink));
router.post("/resend-confirmation", asyncHandler(UserController.resendConfirmation));router.post("/2fa/disable", checkBlacklist, userGuard, asyncHandler(UserController.disable2FA));
// Route DELETE protégée
router.delete("/me", checkBlacklist, userGuard, asyncHandler(UserController.deleteMe));
// 1. Redirige vers Google
router.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

// 2. Retour de Google
// --- ROUTE 1 : Pour le Navigateur (Réel) ---
router.get('/api/auth/google/callback', 
  passport.authenticate('google', { session: false }),
  async (req, res) => {
    try {
      const user = req.user;
      const accessToken = TokenService.generateAccessToken(user);
      const refreshToken = await TokenService.generateRefreshToken(user.id);

      res.json({
        success: true,
        accessToken,
        refreshToken,
        user: { id: user.id, email: user.email, name: user.name }
      });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  }
);

// --- ROUTE 2 : Pour YAAK (Simulation Livrable) ---
// Notez le "router.post" ici
router.post('/api/auth/google/callback', async (req, res) => {
  try {
    const { email, name, providerId } = req.body;

    // Simulation via votre UserService
    const user = await UserService.findOrCreateOAuthUser({
      email,
      name,
      provider: 'google',
      providerId
    });

    const accessToken = TokenService.generateAccessToken(user);
    const refreshToken = await TokenService.generateRefreshToken(user.id);

    res.json({
      success: true,
      accessToken,
      refreshToken,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;