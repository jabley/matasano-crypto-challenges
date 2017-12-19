package main

import "strings"

type Cookies map[string]string

func parseKeyValuePairs(v string) Cookies {
	// TOOD(jabley): defend against bad input
	res := make(map[string]string)
	pairs := strings.Split(v, "&")

	for _, p := range pairs {
		kv := strings.Split(p, "=")
		switch len(kv) {
		// Key with no value
		case 1:
			res[kv[0]] = ""
		// key-value pair
		case 2:
			// Only accept the first occurence
			if _, ok := res[kv[0]]; !ok {
				res[kv[0]] = kv[1]
			}
		// WAT?
		default:
			panic("Unexpected value: " + p)
		}
	}

	return res
}

func (c *Cookies) String() string {
	tmp := make(Cookies)

	// We want a defined order, and go maps don't do that.
	// So we make a copy and mutate it.
	for k, v := range *c {
		tmp[k] = v
	}

	res := ""

	handleKey := func(k string) {
		if v, ok := tmp[k]; ok {
			res += k + "=" + v
			delete(tmp, k)
			if len(tmp) > 0 {
				res += "&"
			}
		}
	}

	// Define an order for these 3 keys, as per the example.
	handleKey("email")
	handleKey("uid")
	handleKey("role")

	// Not bothered about any other entries for now

	return res
}

func ProfileFor(email string) string {
	sanitised := strings.Replace(strings.Replace(email, "&", "", -1), "=", "", -1)
	cookies := make(Cookies)
	cookies["email"] = sanitised
	cookies["uid"] = "10"
	cookies["role"] = "user"
	return cookies.String()
}
