import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import passport from 'passport';

// On charge d'abord les variables d'environnement
dotenv.config();

// Import de la configuration Passport (doit être fait après dotenv.config)
import './config/passport.js'; 

import { logger, httpLogger } from "#lib/logger.js";
import { errorHandler } from "#middlewares/error-handler.js";
import { notFoundHandler } from "#middlewares/not-found.js";
import userRouter from "#routes/user.routes.js";

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middlewares Globaux ---
app.use(helmet());
app.use(cors());
app.use(httpLogger);
app.use(express.json());

// --- Initialisation Passport ---
app.use(passport.initialize()); // Obligatoire avant les routes

// --- Routes ---
app.get("/", (req, res) => {
  res.json({ success: true, message: "API Express opérationnelle avec OAuth" });
});

// Utilisation des routes utilisateurs
app.use("/", userRouter); // Gère /register, /login, /auth/google, etc.

// --- Gestion des Erreurs ---
app.use(notFoundHandler);
app.use(errorHandler);

app.listen(PORT, () => {
  logger.info(`Serveur démarré sur http://localhost:${PORT}`);
});