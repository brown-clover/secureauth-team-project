import express from 'express';
import cors from 'cors';
import authRoutes from './routes/auth.routes.js';
import protectedRoutes from './routes/protected.routes.js';
import twofaRoutes from './routes/2fa.routes.js';



const app = express();

app.use(cors());
app.use(express.json());
app.use('/api/2fa', twofaRoutes);

app.use('/api/auth', authRoutes);
app.use('/api', protectedRoutes);

export default app;
