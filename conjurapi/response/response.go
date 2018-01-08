package response

import (
  "encoding/json"
  "io/ioutil"
  "net/http"
)

func readBody(resp *http.Response) ([]byte, error) {
  defer resp.Body.Close()
  
  responseText, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return nil, err
  }

  return responseText, err
}

func SecretDataResponse(resp *http.Response) ([]byte, error) {
  if resp.StatusCode < 300 {
    return readBody(resp)
  } else {
    return nil, NewConjurError(resp)   
  }  
}

func JSONResponse(resp *http.Response, obj interface{}) (error) {
  if resp.StatusCode < 300 {
    body, err := readBody(resp)
    if err != nil {
      return err
    }
    return json.Unmarshal(body, obj)
  } else {
    return NewConjurError(resp)   
  }  
}

func EmptyResponse(resp *http.Response) (error) {
  if resp.StatusCode < 300 {
    return nil
  } else {
    return NewConjurError(resp)   
  }    
}
