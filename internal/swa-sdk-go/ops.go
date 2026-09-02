package swa

import "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"

// opRetry labels the transient placeholder error the client records between
// retry attempts. It never surfaces to callers and is overwritten by the final
// result on every retry cycle. The public Op catalog lives in swaerrors.
const opRetry swaerrors.Op = "retry"
