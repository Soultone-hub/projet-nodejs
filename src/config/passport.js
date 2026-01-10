import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { UserService } from '../services/user.service.js';

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/api/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // On utilise le service que nous avons déjà créé ensemble
      const user = await UserService.loginWithOAuth({
        email: profile.emails[0].value,
        name: profile.displayName,
        provider: 'google',
        providerId: profile.id // Le VRAI ID Google
      });
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }
));