import { z } from "zod";

export const registerSchema = z.object({
  email: z
    .string()
    .email("Format d'email invalide")
    .toLowerCase() // Normalise l'email pour éviter les doublons (Test@ vs test@)
    .trim(),
  password: z
    .string()
    .min(8, "Le mot de passe doit contenir au moins 8 caractères")
    .regex(/[A-Z]/, "Doit contenir au moins une majuscule")
    .regex(/[0-9]/, "Doit contenir au moins un chiffre"),
  name: z
    .string()
    .min(2, "Le nom doit contenir au moins 2 caractères")
    .max(50)
    .optional(),
});

export const loginSchema = z.object({
  email: z.string().email("Format d'email invalide").toLowerCase().trim(),
  password: z.string().min(1, "Le mot de passe est requis"),
});