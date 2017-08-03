#!/usr/bin/env bash

function finish {
  docker-compose down -v
}
trap finish EXIT

#docker-compose pull postgres possum
#docker-compose build --pull
docker-compose up -d
docker-compose run --rm test ./wait_for_server.sh

api_key=$(docker-compose exec -T possum rails r "print Credentials['cucumber:user:admin'].api_key")

# Execute tests
docker-compose run --rm \
  -p 8080:8080 \
  -e CONJUR_API_KEY="$api_key" \
  test bash -c "./convey.sh& \
                bash"

#if cmdOut, err = exec.Command(cmdName, cmdArgs...).Output(); err != nil {
#		fmt.Fprintln(os.Stderr, "There was an error running git rev-parse command: ", err)
#		os.Exit(1)
#	}
#	sha := string(cmdOut)

secret_identifier="db/password"
response=$(curl --data "$CONJUR_API_KEY" "$CONJUR_APPLIANCE_URL/authn/$CONJUR_ACCOUNT/admin/authenticate")
token=$(echo -n $response | base64 | tr -d '\r\n')
read -r -d '' policy << EOM
- !variable $secret_identifier
EOM
curl -H "Authorization: Token token=\"$token\"" \
     -X POST -d "$policy" \
     "$CONJUR_APPLIANCE_URL/policies/$CONJUR_ACCOUNT/policy/root"


curl -i -H "Authorization: Token token=\"$token\"" \
     --data "secret-value" \
     "$CONJUR_APPLIANCE_URL/secrets/$CONJUR_ACCOUNT/variable/$secret_identifier"


echo $(curl -H "Authorization: Token token=\"$token\"" \
    "$CONJUR_APPLIANCE_URL/secrets/$CONJUR_ACCOUNT/variable/$secret_identifier" \
    ) \
    | jq .

echo $(curl -H "Authorization: Token token=\"$token\"" "$CONJUR_APPLIANCE_URL/resources/$CONJUR_ACCOUNT") | jq .