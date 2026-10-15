import path from 'path';
import { InvestigationSession, InvestigationExportBundle } from '../types/investigation';
import { getRepository, SqliteInvestigationRepository } from './repository';

const DATA_DIR = path.resolve(process.cwd(), 'data');

export function initPersistence(): void {
  // Accessing repository ensures SQLite DB and tables are initialized and cached
  getRepository();
}

export function saveInvestigation(session: InvestigationSession): void {
  getRepository().save(session);
}

export function getInvestigation(id: string): InvestigationSession | null {
  return getRepository().getById(id);
}

export function listInvestigations(): InvestigationSession[] {
  return getRepository().list();
}

export function deleteInvestigation(id: string): boolean {
  return getRepository().delete(id);
}

export function clearMemoryCache(): void {
  getRepository().clearCache();
}

export function getExportBundle(id: string): InvestigationExportBundle | null {
  return getRepository().getExportBundle(id);
}

export function importExportBundle(bundle: InvestigationExportBundle): InvestigationSession {
  return getRepository().importExportBundle(bundle);
}

export function getPersistenceDir(): string {
  return DATA_DIR;
}
