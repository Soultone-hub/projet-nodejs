import { UserService } from "#services/user.service.js";

export class UserController {
  // Cette méthode DOIT exister pour que le router la trouve
  static async register(req, res) {
    const user = await UserService.register(req.body);
    res.status(201).json({
      success: true,
      data: user
    });
  }

  // Ajoute aussi celle-ci pour ne pas avoir d'erreur sur la route /login
  static async login(req, res) {
    const { email, password } = req.body;
    const ip = req.ip || "127.0.0.1";
    const userAgent = req.headers["user-agent"] || "unknown";

    const result = await UserService.login(email, password, ip, userAgent);
    
    res.json({
      success: true,
      data: result
    });
  }


  static async getMe(req, res) {
  // req.user est rempli par le middleware userGuard
  const user = await UserService.getProfile(req.user.id);
  
  res.json({
    success: true,
    data: user
  });
}
}