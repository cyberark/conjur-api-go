package response

import (
  "encoding/json"
  "io/ioutil"
  "net/http"
  "strings"
)

type ConjurError struct {
  Code    int
  Message string
  Details *ConjurErrorDetails `json:"error"`
}

type ConjurErrorDetails struct {
  Message string
  Code    string
  Target  string
  Details map[string]interface{}
}

func NewConjurError(resp *http.Response) (error) {
  defer resp.Body.Close()
  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return err
  }

  cerr := ConjurError{}
  cerr.Code = resp.StatusCode
  err = json.Unmarshal(body, &cerr)
  if err != nil {
    cerr.Message = strings.TrimSpace(string(body))
  }
  return &cerr
}

func (self *ConjurError) Error() string {
  if self.Details != nil && self.Details.Message != "" {
    return self.Details.Message
  } else {
    return self.Message
  }
}
