using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace B2CInvite.Domain
{
    internal class UserData
    {
        public string Email { get; set; }
        public string DisplayName { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        
        private bool IsValidEmail()
        {
            return new EmailAddressAttribute().IsValid(this.Email);
        }

        public bool IsValid()
        {
            bool result = false;

            if (
                IsValidEmail() && 
                (!string.IsNullOrEmpty(this.FirstName)) &&
                (!string.IsNullOrEmpty(this.LastName)) &&
                (!string.IsNullOrEmpty(this.DisplayName))
               )
            {
                result = true;
            }

            return result;
        }
    }
}
