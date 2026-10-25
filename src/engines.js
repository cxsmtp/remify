import { CheckmarxConnector } from './connectors/checkmarx.js';
import { SnykConnector } from './connectors/snyk.js';
import { BlackDuckConnector } from './connectors/blackduck.js';
import { MendConnector } from './connectors/mend.js';
import { WizConnector } from './connectors/wiz.js';
import { AikidoConnector } from './connectors/aikido.js';
import { AppScanConnector } from './connectors/appscan.js';
import { BurpConnector } from './connectors/burp.js';
import { AcunetixConnector } from './connectors/acunetix.js';

export const ENGINES = Object.freeze(
  Object.fromEntries(
    [
      CheckmarxConnector,
      SnykConnector,
      BlackDuckConnector,
      MendConnector,
      WizConnector,
      AikidoConnector,
      AppScanConnector,
      BurpConnector,
      AcunetixConnector,
    ].map((connector) => [connector.id, connector]),
  ),
);
