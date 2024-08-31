package rfc9396_test

import (
	"fmt"

	"github.com/ory/fosite"
)

type PaymentInitiationTypeHandler struct {
	fosite.RFC9396DefaultAuthorizationDetailsTypeHandler
}

func (h *PaymentInitiationTypeHandler) Equals(t1, t2 *fosite.RFC9396AuthorizationDetailsType) bool {
	if len(t1.Extra) != len(t2.Extra) {
		return false
	}

	instructedAmount1 := fosite.Map(t1.Extra).SafeMap("instructedAmount", nil)
	instructedAmount2 := fosite.Map(t2.Extra).SafeMap("instructedAmount", nil)
	if fosite.Map(instructedAmount1).SafeString("currency", "") != fosite.Map(instructedAmount2).SafeString("currency", "") {
		return false
	}

	if fosite.Map(instructedAmount1).SafeString("amount", "") != fosite.Map(instructedAmount2).SafeString("amount", "") {
		return false
	}

	if fosite.Map(t1.Extra).SafeString("creditorName", "") != fosite.Map(t2.Extra).SafeString("creditorName", "") {
		return false
	}

	creditorAccount1 := fosite.Map(t1.Extra).SafeMap("creditorAccount", nil)
	creditorAccount2 := fosite.Map(t2.Extra).SafeMap("creditorAccount", nil)
	if fosite.Map(creditorAccount1).SafeString("bic", "") != fosite.Map(creditorAccount2).SafeString("bic", "") {
		return false
	}

	if fosite.Map(creditorAccount1).SafeString("iban", "") != fosite.Map(creditorAccount2).SafeString("iban", "") {
		return false
	}

	if fosite.Map(t1.Extra).SafeString("remittanceInformationUnstructured", "") != fosite.Map(t2.Extra).SafeString("remittanceInformationUnstructured", "") {
		return false
	}

	return h.RFC9396DefaultAuthorizationDetailsTypeHandler.Equals(t1, t2)
}

func (h *PaymentInitiationTypeHandler) Validate(t *fosite.RFC9396AuthorizationDetailsType) error {
	instructedAmount := fosite.Map(t.Extra).SafeMap("instructedAmount", nil)
	if instructedAmount == nil {
		return fmt.Errorf("instructedAmount is required.")
	}

	if fosite.Map(instructedAmount).SafeString("currency", "") == "" {
		return fmt.Errorf("instructedAmount.currency is required.")
	}

	if fosite.Map(instructedAmount).SafeString("amount", "") == "" {
		return fmt.Errorf("instructedAmount.amount is required.")
	}

	return h.RFC9396DefaultAuthorizationDetailsTypeHandler.Validate(t)
}
