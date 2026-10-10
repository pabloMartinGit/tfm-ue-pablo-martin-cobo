# Enmascarado de datos personales en los decision logs (RU-06): la traza de
# auditoría conserva sub, tenant, roles y decisión, pero no datos de contacto.
package system.log

mask contains "/input/jwt_claims/email"

mask contains "/input/jwt_claims/name"

mask contains "/input/jwt_claims/given_name"

mask contains "/input/jwt_claims/family_name"
