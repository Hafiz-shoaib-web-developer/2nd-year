import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { attachUser, requireAuth } from './server/auth';
import { AVATARS_DIR, BRAND_DIR, db, initDatabase, MATERIALS_DIR, SUBMISSIONS_DIR } from './server/db';
import adminRoutes from './server/routes/adminRoutes';
import authRoutes from './server/routes/authRoutes';
import publicRoutes from './server/routes/publicRoutes';
import studentRoutes from './server/routes/studentRoutes';

dotenv.config();

async function startServer() {
  initDatabase();

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });

  app.use(cookieParser());
  app.use(express.json({ limit: '10mb' }));
  app.use(attachUser);

  app.get('/api/health', (_req, res) => {
    try {
      const ok = db.prepare('SELECT 1 as ok').get() as { ok: number };
      res.json({ status: ok?.ok === 1 ? 'ok' : 'degraded', uptimeSeconds: Math.round(process.uptime()) });
    } catch {
      res.status(503).json({ status: 'error' });
    }
  });

  // API Routes
  app.use('/api', authRoutes);
  app.use('/api', publicRoutes);
  app.use('/api/student', studentRoutes);
  app.use('/api/admin', adminRoutes);

  // Safe avatar & brand media serving
  app.get('/api/media/avatars/:filename', (req, res) => {
    const safeName = path.basename(req.params.filename);
    const fullPath = path.join(AVATARS_DIR, safeName);
    if (!fs.existsSync(fullPath)) {
      res.status(404).json({ error: 'Avatar not found.' });
      return;
    }
    res.sendFile(fullPath);
  });

  app.get('/api/media/brand/:filename', (req, res) => {
    const safeName = path.basename(req.params.filename);
    const fullPath = path.join(BRAND_DIR, safeName);
    if (!fs.existsSync(fullPath)) {
      res.status(404).json({ error: 'Brand asset not found.' });
      return;
    }
    if (safeName.toLowerCase().endsWith('.svg')) {
      res.setHeader('Content-Security-Policy', "sandbox; default-src 'none'; style-src 'unsafe-inline'");
    }
    res.sendFile(fullPath);
  });

  // Authorized Study Material PDF View / Download
  app.get('/api/files/:id/:mode', requireAuth, (req, res) => {
    const materialId = Number(req.params.id);
    if (!Number.isInteger(materialId) || materialId <= 0) {
      res.status(400).json({ error: 'Invalid material ID.' });
      return;
    }
    const mode = req.params.mode;
    if (mode !== 'view' && mode !== 'download') {
      res.status(400).json({ error: 'Invalid file access mode.' });
      return;
    }

    const material = db.prepare('SELECT * FROM study_materials WHERE id = ?').get(materialId) as any;
    if (!material) {
      res.status(404).json({ error: 'Study material not found.' });
      return;
    }

    if (req.user!.role !== 'admin') {
      if (material.is_published !== 1) {
        res.status(403).json({ error: 'This material is currently unpublished.' });
        return;
      }
      const sp = db.prepare('SELECT study_group_id FROM student_profiles WHERE user_id = ?').get(req.user!.id) as
        | { study_group_id: number }
        | undefined;
      if (!sp) {
        res.status(403).json({ error: 'Unauthorized.' });
        return;
      }
      if (material.study_group_id && material.study_group_id !== sp.study_group_id) {
        res.status(403).json({ error: 'Material belongs to a different study group.' });
        return;
      }
      const hasSub = db
        .prepare('SELECT 1 FROM study_group_subjects WHERE study_group_id = ? AND subject_id = ?')
        .get(sp.study_group_id, material.subject_id);
      if (!hasSub) {
        res.status(403).json({ error: 'Subject is not part of your study group.' });
        return;
      }
      if (mode === 'download' && material.allow_download !== 1) {
        res.status(403).json({ error: 'Downloading is disabled for this document. View online only.' });
        return;
      }
    }

    const safeFile = path.basename(material.file_path);
    const fullPath = path.join(MATERIALS_DIR, safeFile);
    if (!fs.existsSync(fullPath)) {
      res.status(404).json({ error: 'Document file missing on server.' });
      return;
    }

    res.setHeader('Content-Type', material.mime_type || 'application/pdf');
    const disp = mode === 'download' ? 'attachment' : 'inline';
    res.setHeader('Content-Disposition', `${disp}; filename="${material.original_filename.replace(/"/g, '')}"`);
    res.sendFile(fullPath);
  });

  // Authorized Assignment Submission Attachment Access (Owner Student or Super Admin ONLY)
  app.get('/api/submissions/:id/attachment', requireAuth, (req, res) => {
    const subId = Number(req.params.id);
    if (!Number.isInteger(subId) || subId <= 0) {
      res.status(400).json({ error: 'Invalid submission ID.' });
      return;
    }
    const sub = db.prepare('SELECT * FROM assignment_submissions WHERE id = ?').get(subId) as any;
    if (!sub || !sub.attachment_path) {
      res.status(404).json({ error: 'Submission attachment not found.' });
      return;
    }
    if (req.user!.role !== 'admin' && sub.student_id !== req.user!.id) {
      res.status(403).json({ error: 'Access denied to another student’s submission.' });
      return;
    }
    const safeFile = path.basename(sub.attachment_path);
    const fullPath = path.join(SUBMISSIONS_DIR, safeFile);
    if (!fs.existsSync(fullPath)) {
      res.status(404).json({ error: 'Attachment file missing.' });
      return;
    }
    res.setHeader('Content-Type', sub.attachment_mime || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${(sub.attachment_name || safeFile).replace(/"/g, '')}"`);
    res.sendFile(fullPath);
  });

  // API 404 Catch-all
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found.' });
  });

  // Error handler for Multer & API errors
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (req.path.startsWith('/api')) {
      res.status(err?.status || 400).json({ error: err?.message || 'Request failed.' });
      return;
    }
    next(err);
  });

  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = Number(process.env.PORT || 3000);
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Second Year Hub server running at http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start Second Year Hub server:', err);
  process.exit(1);
});
