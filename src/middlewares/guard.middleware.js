import { verifyAccessToken } from "#lib/jwt.js";
import { UnauthorizedException } from "#lib/exceptions.js";

export const userGuard = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(new UnauthorizedException("Token manquant ou format invalide"));
  }

  const token = authHeader.split(" ")[1];
  const payload = await verifyAccessToken(token);

  if (!payload) {
    return next(new UnauthorizedException("Token invalide ou expiré"));
  }

  // On attache l'ID de l'utilisateur à la requête pour les étapes suivantes
  req.user = { id: payload.id };
  next();
};