package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("utils", func() {

	Context("subDomainValid", func() {

		It("should invalidate empty subdomain", func() {
			for _, subDomain := range []string{"", "   "} {
				valid := subDomainValid(subDomain)
				Expect(valid).To(BeFalse())
			}
		})

		It("should validate subdomains", func() {
			for _, subDomain := range []string{"abcd", "my-sub"} {
				valid := subDomainValid(subDomain)
				Expect(valid).To(BeTrue())
			}
		})

		It("should invalidate multiple consecutive dashes", func() {
			for _, subDomain := range []string{"a--c", "abc-d--r"} {
				valid := subDomainValid(subDomain)
				Expect(valid).To(BeFalse())
			}
		})

		It("should validate multiple separate dashes", func() {
			for _, subDomain := range []string{"a-b-c", "abc-d-r"} {
				valid := subDomainValid(subDomain)
				Expect(valid).To(BeTrue())
			}
		})

		It("should invalidate subdomains with invalid chars", func() {
			for _, subDomain := range []string{"a*bcd", "dsdsfs.fsdfd"} {
				valid := subDomainValid(subDomain)
				Expect(valid).To(BeFalse())
			}
		})

		It("should invalidate subdomains beginning or ending with a dash", func() {
			for _, subDomain := range []string{"-a-b-c", "abc-d-r-"} {
				valid := subDomainValid(subDomain)
				Expect(valid).To(BeFalse())
			}
		})
	})

	Context("extractSubdomain from host", func() {

		It("should error on empty subdomain", func() {
			for _, host := range []string{domain} {
				_, err := extractSubdomain(host)
				Expect(err).To(HaveOccurred())
			}
		})

		It("should extract subdomain", func() {
			for _, host := range []string{"abc." + domain} {
				s, err := extractSubdomain(host)
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("abc"))
			}
		})

		It("should extract subdomain", func() {
			for _, host := range []string{"open-idc." + domain} {
				s, err := extractSubdomain(host)
				Expect(err).To(Not(HaveOccurred()))
				Expect(s).To(Equal("open-idc"))
			}
		})
	})

})
