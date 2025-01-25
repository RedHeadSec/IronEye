use crate::args::TgtArguments;
use krb5_sys::*;
use std::ffi::CString;
use std::ptr;

pub fn get_tgt(args: TgtArguments) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // Initialize Kerberos context
        let mut ctx: krb5_context = ptr::null_mut();
        if krb5_init_context(&mut ctx) != 0 {
            return Err("Failed to initialize Kerberos context".into());
        }

        // Build principal (username@REALM)
        let mut principal: krb5_principal = ptr::null_mut();
        let principal_name = CString::new(format!("{}@{}", args.username, args.realm))?;
        if krb5_parse_name(ctx, principal_name.as_ptr(), &mut principal) != 0 {
            krb5_free_context(ctx);
            return Err("Failed to parse principal name".into());
        }

        // Create credentials cache in the current directory
        let ccache_path = format!("./{}.ccache", args.username); // Default local file
        let ccache_path_c = CString::new(ccache_path.clone())?;
        let mut ccache: krb5_ccache = ptr::null_mut();
        if krb5_cc_resolve(ctx, ccache_path_c.as_ptr(), &mut ccache) != 0 {
            krb5_free_principal(ctx, principal);
            krb5_free_context(ctx);
            return Err("Failed to create credentials cache".into());
        }

        // Acquire TGT
        let password_c = CString::new(args.password.clone())?;
        let mut creds: krb5_creds = std::mem::zeroed();
        let options: krb5_get_init_creds_opt = std::mem::zeroed();

        let ret = krb5_get_init_creds_password(
            ctx,
            &mut creds,
            principal,
            password_c.as_ptr(),
            None,
            ptr::null_mut(),
            0,
            ptr::null(),
            &options,
        );

        if ret != 0 {
            krb5_free_principal(ctx, principal);
            krb5_cc_close(ctx, ccache);
            krb5_free_context(ctx);
            return Err(format!("Failed to acquire TGT: error code {}", ret).into());
        }

        // Store credentials in the cache
        if krb5_cc_initialize(ctx, ccache, principal) != 0
            || krb5_cc_store_cred(ctx, ccache, &mut creds) != 0
        {
            krb5_free_principal(ctx, principal);
            krb5_cc_close(ctx, ccache);
            krb5_free_context(ctx);
            return Err("Failed to store TGT in credentials cache".into());
        }

        println!(
            "TGT successfully saved to local credentials cache: {}",
            ccache_path
        );

        // Cleanup
        krb5_free_principal(ctx, principal);
        krb5_free_cred_contents(ctx, &mut creds);
        krb5_cc_close(ctx, ccache);
        krb5_free_context(ctx);
    }

    Ok(())
}
