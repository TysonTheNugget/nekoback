// Local wrapper that exposes the function your page calls.
// No window globals from CDNs needed.
import { createInscription } from "@sats-connect/core";

if (!window.SatsConnect) window.SatsConnect = {};
window.SatsConnect.createInscription = createInscription;
