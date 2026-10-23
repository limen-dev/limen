//! Open a configured web resource in the user's browser (ADR-0022).

use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;

use crate::{api, ui};

pub async fn open(proxy: Option<&str>, app: &str, no_browser: bool) -> anyhow::Result<()> {
    let (_, channel) = api::authenticated(proxy)?;
    let response = ResourcesClient::new(channel)
        .list_resources(ListResourcesRequest {})
        .await
        .map_err(|status| api::status_error(&status))?
        .into_inner();
    let Some(resource) = response
        .resources
        .iter()
        .find(|resource| resource.name == app)
    else {
        anyhow::bail!("web app {app:?} is not available to this login; run `limen ls`");
    };
    if resource.kind != "web" {
        anyhow::bail!("resource {app:?} is {}, not a web app", resource.kind);
    }
    if resource.web_url.is_empty() {
        anyhow::bail!("browser SSO is not configured for web app {app:?}");
    }
    let url = http::Uri::try_from(resource.web_url.as_str()).map_err(|error| {
        anyhow::anyhow!("control plane returned an invalid web app URL: {error}")
    })?;
    if url.scheme_str() != Some("https")
        || url.authority().is_none()
        || url
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        || url.path() != "/"
        || url.query().is_some()
        || url.to_string().contains('#')
    {
        anyhow::bail!("browser SSO is not configured for web app {app:?}");
    }
    let url = resource.web_url.as_str();
    if no_browser {
        println!("{url}");
    } else {
        webbrowser::open(url).map_err(|error| {
            anyhow::anyhow!("could not open web app {app:?} in a browser: {error}")
        })?;
        ui::success(&format!("Opened {app} in your browser."));
    }
    Ok(())
}
