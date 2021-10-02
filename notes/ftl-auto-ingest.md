


# ftl auto ingest selection notes

## conclusion, unusable in Vanilla OBS builds due to hardcoded .mixer url
Could patch to use derivative of hostname, but difficult to get (impossible) to get into OBS build.


Controlled in code with #define DISABLE_AUTO_INGEST x

Appears to be enabled in OBS vanilla builds. (Not 100%)
https://github.com/obsproject/obs-studio/issues/5140 (search INGEST_LIST_URI)

Puts channel ID in URL.
https://github.com/microsoft/ftl-sdk/blob/master/libftl/ftl_private.h#L77

Is hardcoded to some Mixer-based URL, and is

#define INGEST_LIST_URI "https://conductor.videosvc.mixer.com/api/video/v2/channels/%d/ingest"

'auto' for hostname will trigger auto-ingest process.
https://github.com/microsoft/ftl-sdk/blob/master/libftl/ftl_helpers.c#L270


