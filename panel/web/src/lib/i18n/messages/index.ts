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
};
