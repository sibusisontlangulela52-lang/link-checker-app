import { createClient } from "@supabase/supabase-js";
 
// These two values are PUBLIC by design (they end up in the browser).
// Use the Project URL and the PUBLISHABLE key here - never the secret key.
export const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY
);