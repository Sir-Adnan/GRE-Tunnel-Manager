// Feature message modules. Keys are global, so each key lives in exactly one module (tests enforce it).
import { common } from "./common";
import { overview } from "./overview";
import { connections } from "./connections";
import { traffic } from "./traffic";
import { nodes } from "./nodes";
import { resources } from "./resources";
import { backups } from "./backups";
import { system } from "./system";
import { login } from "./login";
import { health } from "./health";
import { maintenance } from "./maintenance";
import { optimize } from "./optimize";
import { notifications } from "./notifications";
import { history } from "./history";
import { tunnels } from "./tunnels";
import { forwarding } from "./forwarding";
import { serverdns } from "./serverdns";
import { access } from "./access";
import { firewall } from "./firewall";
import { addresses } from "./addresses";
import { check } from "./check";
import { errorhelp } from "./errorhelp";
import { templates } from "./templates";
import { signin } from "./signin";
import { server } from "./server";
import { wizard } from "./wizard";

export const modules = {
  access,
  common,
  overview,
  connections,
  traffic,
  nodes,
  resources,
  backups,
  system,
  login,
  health,
  maintenance,
  optimize,
  notifications,
  history,
  tunnels,
  forwarding,
  serverdns,
  firewall,
  addresses,
  check,
  errorhelp,
  templates,
  signin,
  server,
  wizard,
};

export const messages = {
  ...access,
  ...common,
  ...overview,
  ...connections,
  ...traffic,
  ...nodes,
  ...resources,
  ...backups,
  ...system,
  ...login,
  ...health,
  ...maintenance,
  ...optimize,
  ...notifications,
  ...history,
  ...tunnels,
  ...forwarding,
  ...serverdns,
  ...firewall,
  ...addresses,
  ...check,
  ...errorhelp,
  ...templates,
  ...signin,
  ...server,
  ...wizard,
};
