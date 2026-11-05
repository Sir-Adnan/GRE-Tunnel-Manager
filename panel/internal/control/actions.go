package control

// One registry classifies every broker action. The public HTTP allowlist, the
// broker's locking/lifetime policy, the audit filter and the /backup endpoint
// routing all derive from it, so a new action cannot be added to one list and
// silently missed by another.
type actionSpec struct {
	// read actions change no configuration or system state. They are served
	// without the mutation lock, keep the caller's context and are not audited.
	read bool
	// public actions may be started by an authenticated browser through
	// /api/operations. Reads are exposed through dedicated GET routes instead.
	public bool
	// backup actions use the larger, separate /backup broker endpoint.
	backup bool
	// light actions change only panel bookkeeping (notification read marks)
	// under their own lock: no mutation lock, no audit, a direct POST route.
	light bool
}

var actions = map[string]actionSpec{
	"host-telemetry":              {read: true},
	"inventory":                   {read: true},
	"capabilities":                {read: true},
	"metrics":                     {read: true},
	"metrics-history":             {read: true},
	"configuration":               {read: true},
	"configuration-review":        {read: true},
	"configuration-import-review": {read: true},
	"engine-releases":             {read: true},
	"health":                      {read: true},
	"health-report":               {read: true},
	"maintenance":                 {read: true},
	"health-flows":                {read: true},
	"health-mtu":                  {read: true},
	"optimize":                    {read: true},
	"optimize-plan":               {read: true},
	"notifications":               {read: true},
	"history":                     {read: true},
	"history-review":              {read: true},
	"diagnose":                    {read: true},
	"gre-quality":                 {read: true},
	"node-probes":                 {read: true},
	"snapshots":                   {read: true},
	"prometheus":                  {read: true},
	"prometheus-settings":         {read: true},
	"dns":                         {read: true},
	"dns-test":                    {read: true},
	"dns-resolve":                 {read: true},
	"ui-order":                    {read: true},
	"change-pending":              {read: true},

	"notifications-read":  {light: true},
	"notifications-clear": {light: true},
	"ui-order-save":       {light: true},

	"create":                     {public: true},
	"update":                     {public: true},
	"enable":                     {public: true},
	"disable":                    {public: true},
	"delete":                     {public: true},
	"plan":                       {public: true},
	"doctor":                     {public: true},
	"install":                    {public: true},
	"gre-create":                 {public: true},
	"gre-delete":                 {public: true},
	"reverse-create":             {public: true},
	"reverse-delete":             {public: true},
	"service":                    {public: true},
	"logs":                       {public: true},
	"metrics-configure":          {public: true},
	"metrics-reset":              {public: true},
	"metrics-policy":             {public: true},
	"metrics-forget":             {public: true},
	"resource-rename":            {public: true},
	"configuration-apply":        {public: true},
	"configuration-import-apply": {public: true},
	"engine-update":              {public: true},
	"health-configure":           {public: true},
	"maintenance-configure":      {public: true},
	"maintenance-save":           {public: true},
	"maintenance-delete":         {public: true},
	"maintenance-run":            {public: true},
	"maintenance-cancel":         {public: true},
	"optimize-apply":             {public: true},
	"optimize-undo":              {public: true},
	"optimize-remove":            {public: true},
	"notifications-configure":    {public: true},
	"notifications-test":         {public: true},
	"history-restore":            {public: true},
	"snapshots-configure":        {public: true},
	"snapshots-run":              {public: true},
	"snapshots-delete":           {public: true},
	"prometheus-configure":       {public: true},
	"dns-apply":                  {public: true},
	"health-protect":             {public: true},
	"dns-restore":                {public: true},
	"dns-policy":                 {public: true},
	"dns-refresh":                {public: true},
	"change-confirm":             {public: true},
	"change-revert":              {public: true},

	"backup-export":   {backup: true},
	"backup-review":   {backup: true},
	"backup-restore":  {backup: true},
	"backup-snapshot": {backup: true},

	"node-task": {},
}

// ReadAction reports whether an action is a side-effect-free read.
func ReadAction(action string) bool { return actions[action].read }

// PublicOperation reports whether a browser may start the action as a job.
func PublicOperation(action string) bool { return actions[action].public }

// LightAction reports whether the action only changes panel bookkeeping.
func LightAction(action string) bool { return actions[action].light }

// BackupAction reports whether the action belongs to the /backup endpoint.
func BackupAction(action string) bool { return actions[action].backup }
