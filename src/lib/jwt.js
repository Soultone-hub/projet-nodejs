import { SignJWT } from "jose";

const secret = new TextEncoder().encode(process.env.JWT_SECRET);

export const generateAccessToken = async (payload) => {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("15m") // Expire vite
    .sign(secret);
};

export const generateRefreshToken = async (payload) => {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("7d") // Session de 7 jours
    .sign(secret);
};

export const verifyAccessToken = async (token) => {
  try {
    const { payload } = await jwtVerify(token, secret);
    return payload;
  } catch (error) {
    return null;
  }
};