import { SignJWT, jwtVerify } from "jose"; // AJOUT de jwtVerify ici
import "dotenv/config";

const secretKey = process.env.JWT_SECRET || "ma_super_cle_secrete_de_secours_32_caracteres";
const secret = new TextEncoder().encode(secretKey);

export const generateAccessToken = async (payload) => {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(secret);
};

export const generateRefreshToken = async (payload) => {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(secret);
};

export const verifyAccessToken = async (token) => {
  try {
    // Utilisation correcte de jwtVerify importé
    const { payload } = await jwtVerify(token, secret);
    return payload;
  } catch (error) {
    return null;
  }
};