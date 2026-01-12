import jwt from 'jsonwebtoken';
import prisma from '#lib/prisma.js'; 
import { randomBytes } from 'node:crypto'; // Importation directe de la fonction

export class TokenService {
  static generateAccessToken(user) {
    return jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '15m' }
    );
  }

  static async generateRefreshToken(userId) {
    // Utilisation directe de la fonction importée
    const token = randomBytes(40).toString('hex'); 
    
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    return await prisma.refreshToken.create({
      data: {
        token,
        userId,
        expiresAt
      }
    });
  }
}