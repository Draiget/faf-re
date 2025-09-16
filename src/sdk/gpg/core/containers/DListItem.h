#pragma once

namespace gpg::core
{
	template<class T>
	struct DListItem
	{
		using type = T;

		DListItem<type>* prev;
		DListItem<type>* next;

		DListItem() :
			prev{ this },
			next{ this }
		{
		}

		~DListItem() = default;

        void ListUnlink() {
            prev->next = next;
            next->prev = prev;
            next = this;
            prev = this;
        } 

        void ListLinkBefore(type* that) {
            ListUnlink();
            prev = that->prev;
            next = that;
            prev = this;
            prev->next = this;
        }

        void ListLinkAfter(type* that) {
            ListUnlink();
            prev = that;
            next = that->next_;
            next->prev = this;
            prev->next = this;
        }

        bool ListIsUnlinked() {
            return next == this;
        }

        type* Get() {
            return static_cast<type*>(this);
        }

        bool HasNext() {
            return prev != next;
        }
	};
}