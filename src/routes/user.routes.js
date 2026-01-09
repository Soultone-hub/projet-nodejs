import { Router } from "express";
import { UserController } from "#controllers/user.controller.js";
import { asyncHandler } from "#lib/async-handler.js";
import { userGuard } from "#middlewares/guard.middleware.js";
import { checkBlacklist } from "#middlewares/auth.middleware.js";

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
router.post("/confirm-account", asyncHandler(UserController.confirmAccount));
router.post("/resend-confirmation", asyncHandler(UserController.resendConfirmation));
router.post("/2fa/disable", checkBlacklist, userGuard, asyncHandler(UserController.disable2FA));
// Route DELETE protégée
router.delete("/me", checkBlacklist, userGuard, asyncHandler(UserController.deleteMe));
export default router;