package dhparam

import (
	"math/big"

	"github.com/pkg/errors"
)

const dh_check_p_not_prime = 0x01
const dh_check_p_not_safe_prime = 0x02
const dh_unable_to_check_generator = 0x04
const dh_not_suitable_generator = 0x08
const dh_check_q_not_prime = 0x10
const dh_check_invalid_q_value = 0x20
const dh_check_invalid_j_value = 0x40

// ErrAllParametersOK is defined to check whether the returned error from Check is indeed no error
// For simplicity reasons it is defined as an error instead of an additional result parameter
var ErrAllParametersOK = errors.New("DH parameters appear to be ok.")

// Check returns a number of errors and an "ok" bool. If the "ok" bool is set to true, still one
// error is returned: ErrAllParametersOK. If "ok" is false, the error list will contain at least
// one error not being equal to ErrAllParametersOK.
func (d DH) Check() ([]error, bool) {
	var (
		result = []error{}
		ok     = true
	)

	i := d.check()

	if i&dh_check_p_not_prime > 0 {
		result = append(result, errors.New("WARNING: p value is not prime"))
		ok = false
	}

	if i&dh_check_p_not_safe_prime > 0 {
		result = append(result, errors.New("WARNING: p value is not a safe prime"))
		ok = false
	}

	if i&dh_check_q_not_prime > 0 {
		result = append(result, errors.New("WARNING: q value is not a prime"))
		ok = false
	}

	if i&dh_check_invalid_q_value > 0 {
		result = append(result, errors.New("WARNING: q value is invalid"))
		ok = false
	}

	if i&dh_check_invalid_j_value > 0 {
		result = append(result, errors.New("WARNING: j value is invalid"))
		ok = false
	}

	if i&dh_unable_to_check_generator > 0 {
		result = append(result, errors.New("WARNING: unable to check the generator value"))
		ok = false
	}

	if i&dh_not_suitable_generator > 0 {
		result = append(result, errors.New("WARNING: the g value is not a generator"))
		ok = false
	}

	if i == 0 {
		result = append(result, ErrAllParametersOK)
	}

	return result, ok
}

func (d DH) check() int {
	var ret int

	// Check generator
	switch d.G {
	case 2:
		l := new(big.Int)
		if l.Mod(d.P, big.NewInt(24)); l.Int64() != 11 {
			ret |= DH_NOT_SUITABLE_GENERATOR
		}
	case 5:
		l := new(big.Int)
		if l.Mod(d.P, big.NewInt(10)); l.Int64() != 3 && l.Int64() != 7 {
			ret |= DH_NOT_SUITABLE_GENERATOR
		}
	default:
		ret |= DH_UNABLE_TO_CHECK_GENERATOR
	}

	if !d.P.ProbablyPrime(1) {
		ret |= DH_CHECK_P_NOT_PRIME
	} else {
		t1 := new(big.Int)
		t1.Rsh(d.P, 1)
		if !t1.ProbablyPrime(1) {
			ret |= DH_CHECK_P_NOT_SAFE_PRIME
		}
	}

	return ret
}
