package main

import (
	"net/url"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("utils", func() {

	Context("subDomainValid", func() {

		It("should invalidate empty subdomain", func() {
			for _, subDomain := range []string{"", "   "} {
				valid := tunnelNameValid(subDomain)
				Expect(valid).To(BeFalse())
			}
		})

		It("should validate subdomains", func() {
			for _, subDomain := range []string{"abcd", "my-sub"} {
				valid := tunnelNameValid(subDomain)
				Expect(valid).To(BeTrue())
			}
		})

		It("should invalidate multiple consecutive dashes", func() {
			for _, subDomain := range []string{"a--c", "abc-d--r"} {
				valid := tunnelNameValid(subDomain)
				Expect(valid).To(BeFalse())
			}
		})

		It("should validate multiple separate dashes", func() {
			for _, subDomain := range []string{"a-b-c", "abc-d-r"} {
				valid := tunnelNameValid(subDomain)
				Expect(valid).To(BeTrue())
			}
		})

		It("should invalidate subdomains with invalid chars", func() {
			for _, subDomain := range []string{"a*bcd", "dsdsfs.fsdfd"} {
				valid := tunnelNameValid(subDomain)
				Expect(valid).To(BeFalse())
			}
		})

		It("should invalidate subdomains beginning or ending with a dash", func() {
			for _, subDomain := range []string{"-a-b-c", "abc-d-r-"} {
				valid := tunnelNameValid(subDomain)
				Expect(valid).To(BeFalse())
			}
		})
	})

	Context("extractSubdomain from host", func() {

		It("should error on empty subdomain", func() {
			for _, host := range []string{domainURL} {
				_, err := extractSubdomain(host)
				Expect(err).To(HaveOccurred())
			}
		})

		It("should extract subdomain", func() {
			for _, host := range []string{"abc." + domainURL} {
				s, err := extractSubdomain(host)
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("abc"))
			}
		})

		It("should extract subdomain", func() {
			for _, host := range []string{"open-idc." + domainURL} {
				s, err := extractSubdomain(host)
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("open-idc"))
			}
		})
	})

	Context("extractTunelNameFromURLPath from URL path", func() {

		It("should error when tunnelName not found in domainURL", func() {
			domainURL, _ := url.Parse("http://domain.io/x/y/z")
			for _, value := range []string{"/a/y/z/tunnel/c", "a/y/z/tunnel/c"} {
				_, err := extractTunnelNameFromURLPath(value, *domainURL)
				Expect(err).To(HaveOccurred())
			}
		})

		It("should extract tunnelName when domainURL has path", func() {
			domainURL, _ := url.Parse("http://domain.io/x/y/z")
			for _, value := range []string{"/x/y/z/tunnel/c", "x/y/z/tunnel/c"} {
				s, err := extractTunnelNameFromURLPath(value, *domainURL)
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("tunnel"))
			}
		})

		It("should extract tunnelName when domainURL has no path", func() {
			domainURL, _ := url.Parse("https://domain.io")
			for _, value := range []string{"/x/y/z/tunnel", "x/y/z/tunnel"} {
				s, err := extractTunnelNameFromURLPath(value, *domainURL)
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("x"))
			}
		})

		It("should extract tunnelName when domainURL has empty path", func() {
			domainURL, _ := url.Parse("https://domain.io/")
			for _, value := range []string{"/x/y/z/tunnel", "x/y/z/tunnel"} {
				s, err := extractTunnelNameFromURLPath(value, *domainURL)
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("x"))
			}
		})

	})

	Context("replaceRequestURL", func() {
		It("should replace request URL when requestURL has a relative path", func() {

			for _, value := range []string{"/x/y/z/tunnel/c"} {
				s, err := replaceRequestURL(value, nil, "/x/y/z/tunnel")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("/c"))

				s, err = replaceRequestURL(value, nil, "x/y/z/tunnel")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("/c"))

				newDomain := "localhost"
				s, err = replaceRequestURL(value, &newDomain, "/x/y/z/tunnel")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("/c"))
			}
		})

		It("should replace request URL when requestURL has an absolute path", func() {
			for _, value := range []string{"https://localhost:123/x/y/z/tunnel/c"} {
				s, err := replaceRequestURL(value, nil, "/x/y/z/tunnel")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("https://localhost:123/c"))

				s, err = replaceRequestURL(value, nil, "x/y/z/tunnel")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("https://localhost:123/c"))

				newDomain := "newdomain:456"
				s, err = replaceRequestURL(value, &newDomain, "/x/y/z/tunnel")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("https://newdomain:456/c"))

			}
		})

		It("should replace request URL when requestURL has an absolute path without prefix path", func() {
			for _, value := range []string{"https://localhost:123/x/y/z/tunnel/c"} {
				s, err := replaceRequestURL(value, nil, "")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("https://localhost:123/x/y/z/tunnel/c"))

				s, err = replaceRequestURL(value, nil, "/")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("https://localhost:123/x/y/z/tunnel/c"))

				newDomain := "newdomain:456"
				s, err = replaceRequestURL(value, &newDomain, "")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("https://newdomain:456/x/y/z/tunnel/c"))

			}
		})

		It("should replace request URL when requestURL has an empty path", func() {
			for _, value := range []string{"/"} {
				s, err := replaceRequestURL(value, nil, "/")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("/"))

			}

			for _, value := range []string{"/"} {
				s, err := replaceRequestURL(value, nil, "")
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("/"))
			}
		})

	})

})
