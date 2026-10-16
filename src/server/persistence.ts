import path from 'path';
import { InvestigationSession, InvestigationExportBundle } from '../types/investigation';
import { getRepository, SqliteInvestigationRepository } from './repository';

const DATA_DIR = path.resolve(process.cwd(), 'data');

export function initPersistence(): void {
  // Accessing repository ensures initialization
  getRepository();
}

export async function saveInvestigation(session: InvestigationSession, ownerUid: string = 'system_operator'): Promise<void> {
  await getRepository().save(session, ownerUid);
}

export async function getInvestigation(id: string, requesterUid?: string): Promise<InvestigationSession | null> {
  return await getRepository().getById(id, requesterUid);
}

export async function listInvestigations(requesterUid?: string): Promise<InvestigationSession[]> {
  return await getRepository().list(requesterUid);
}

export async function deleteInvestigation(id: string, requesterUid?: string): Promise<boolean> {
  return await getRepository().delete(id, requesterUid);
}

export async function clearMemoryCache(): Promise<void> {
  await getRepository().clearCache();
}

export async function getExportBundle(id: string, requesterUid?: string): Promise<InvestigationExportBundle | null> {
  return await getRepository().getExportBundle(id, requesterUid);
}

export async function importExportBundle(bundle: InvestigationExportBundle, ownerUid: string): Promise<InvestigationSession> {
  return await getRepository().importExportBundle(bundle, ownerUid);
}

export function getPersistenceDir(): string {
  return DATA_DIR;
}
