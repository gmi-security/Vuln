import {createHash} from 'node:crypto';
import type {ScannerRoute} from './customer-scanner-routing';
// Retained with a completed scan so a later routing change cannot reuse its negatives.
export function nessusEvidenceScope(route:ScannerRoute){
  return createHash('sha256').update(JSON.stringify([route.companyId,route.candidateId,route.connectionRef,
    route.sourceScope,route.revision,route.bindingRevision,[...route.targets].sort()])).digest('hex');
}
