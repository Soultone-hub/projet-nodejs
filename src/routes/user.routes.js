import { Router } from "express";
import { UserController } from "#controllers/user.controller.js";
import { asyncHandler } from "#lib/async-handler.js";
import { userGuard } from "#middlewares/guard.middleware.js";
const router = Router();

// Inscription et Connexion
router.post("/register", asyncHandler(UserController.register));
router.post("/login", asyncHandler(UserController.login));

// Profil utilisateur (protégé)
router.get("/me", userGuard, asyncHandler(UserController.getMe));


export default router;
