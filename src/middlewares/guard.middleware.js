import { jwtVerify } from "jose";

// On recrée la même clé que dans ton fichier jwt.js
const secretKey = process.env.JWT_SECRET || "ma_super_cle_secrete_de_secours_32_caracteres";
const secret = new TextEncoder().encode(secretKey);
export const userGuard = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, error: "Accès refusé" });
  }

  const token = authHeader.split(" ")[1];

  try {
    // On utilise jose pour vérifier le token
    const { payload } = await jwtVerify(token, secret);
    
    // On stocke les infos décodées dans req.user pour le contrôleur
    req.user = payload; 
    
    next();
  } catch (error) {
    return res.status(401).json({ 
      success: false, 
      error: "Token invalide ou expiré",
      message: error.message 
    });
  }
};