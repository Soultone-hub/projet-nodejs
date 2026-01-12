import prisma from "#lib/prisma.js";
export const checkBlacklist = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (token) {
    // Maintenant "prisma" sera défini ici
    const isBlacklisted = await prisma.blacklistedAccessToken.findUnique({
      where: { token }
    });

    if (isBlacklisted) {
      return res.status(401).json({ 
        success: false, 
        message: "Token révoqué. Veuillez vous reconnecter." 
      });
    }
  }
  next();
};