import { Router } from "express";
import { UserController } from "#controllers/user.controller.js";

import { asyncHandler } from "#lib/async-handler.js";
const router = Router();

// Inscription et Connexion
router.post("/register", asyncHandler(UserController.register));
router.post("/login", asyncHandler(UserController.login));


export default router;
